use std::{collections::VecDeque, future::Future};

use futures::{stream::FuturesUnordered, Stream, StreamExt};
use hashbrown::{Equivalent, HashSet};
use opcua_types::{BrowseDescription, BrowseDirection, ByteString, Error, NodeId, StatusCode};

use crate::{
    session::{Browse, BrowseNext},
    RequestRetryPolicy, Session,
};

use super::{result::BrowserResult, BrowseResultItem, Browser, BrowserPolicy, RequestWithRetries};

impl<'a, T: BrowserPolicy + 'a, R: RequestRetryPolicy + Clone + 'a> Browser<'a, T, R> {
    /// Start the browser, returning a stream of results.
    ///
    /// To stop browsing you can simply stop polling this stream.
    pub fn run(
        self,
        initial: Vec<BrowseDescription>,
    ) -> impl Stream<Item = Result<BrowseResultItem, Error>> + 'a {
        // Streams are really hard.
        // This code isn't ideal. Ideally most of this would be inside a method in
        // `BrowserExecution`, but that isn't possible due to there being no way
        // to name the future. We could box it, but that hits a compiler bug.
        // This can hopefully be improved once either RTN, TAIT or ATPIT lands.

        let initial_exec = BrowserExecution {
            browser: self,
            running_browses: FuturesUnordered::new(),
            pending: initial
                .into_iter()
                .map(|r| RequestWithRetries {
                    request: r,
                    num_outer_retries: 0,
                    depth: 0,
                })
                .collect(),
            pending_out: VecDeque::new(),
            browsed_nodes: HashSet::new(),
            pending_continuation_points: HashSet::new(),
        };
        futures::stream::try_unfold(initial_exec, |mut s| async move {
            loop {
                // If we're cancelled, cleanup and stop immediately.
                if s.browser.token.is_cancelled() {
                    s.cleanup().await;
                    return Ok(None);
                }

                // If there is something in the pending outputs, return that first.
                if let Some(n) = s.pending_out.pop_front() {
                    return Ok(Some((n, s)));
                }

                // If there is something in the queue, and there is space for more requests,
                // make some new requests.
                while s.running_browses.len() < s.browser.config.max_concurrent_requests
                    || s.browser.config.max_concurrent_requests == 0
                {
                    let mut chunk = Vec::new();
                    while chunk.len() < s.browser.config.max_nodes_per_request
                        || s.browser.config.max_nodes_per_request == 0
                    {
                        let Some(it) = s.pending.pop_front() else {
                            break;
                        };
                        chunk.push(it);
                    }
                    if !chunk.is_empty() {
                        s.running_browses.push(run_browse(
                            s.browser.session,
                            BrowseBatch::Browse(chunk),
                            s.browser.retry_policy.clone(),
                            s.browser.config.max_references_per_node,
                        ));
                    } else {
                        break;
                    }
                }

                // Nothing more to do, wait until we get a response.
                let Some(next) = s.running_browses.next().await else {
                    return Ok(None);
                };

                // Process the result message, cancelling early if it was a fatal error.
                let browse_next = match next.and_then(|m| s.process_result(m)) {
                    Ok(next) => next,
                    Err(e) => {
                        s.cleanup().await;
                        return Err(e);
                    }
                };

                // If we returned a browse next, enqueue that immediately. There will be space,
                // since we just consumed a future. This means that BrowseNext is prioritized, which is
                // important to avoid overusing continuation points.
                if !browse_next.is_empty() {
                    s.running_browses.push(run_browse(
                        s.browser.session,
                        BrowseBatch::Next(browse_next),
                        s.browser.retry_policy.clone(),
                        s.browser.config.max_references_per_node,
                    ));
                }
            }
        })
    }

    /// Run the browser, collecting the results into a [BrowserResult] struct.
    pub async fn run_into_result(
        self,
        initial: Vec<BrowseDescription>,
    ) -> Result<BrowserResult, Error> {
        BrowserResult::build_from_browser(self.run(initial)).await
    }
}

// It's tricky to store futures in a struct without boxing them, because
// they are un-nameable. In this case, `TFut` is always the future returned by `run_browse`.
// In the future, Type Alias Impl Trait (TAIT), or Return Type Notation (RTN) will make it
// possible to name these types.
struct BrowserExecution<'a, T, R, TFut> {
    browser: Browser<'a, T, R>,
    running_browses: FuturesUnordered<TFut>,
    pending: VecDeque<RequestWithRetries>,
    pending_out: VecDeque<BrowseResultItem>,
    browsed_nodes: HashSet<BrowsedNode>,
    pending_continuation_points: HashSet<ByteString>,
}

#[derive(PartialEq, Eq, Hash)]
enum Direction {
    Forward,
    Inverse,
    Both,
}

#[derive(PartialEq, Eq, Hash)]
struct BrowsedNode {
    id: NodeId,
    direction: Direction,
}

impl From<&BrowseDescription> for BrowsedNode {
    fn from(value: &BrowseDescription) -> Self {
        Self {
            id: value.node_id.clone(),
            direction: match value.browse_direction {
                BrowseDirection::Forward => Direction::Forward,
                BrowseDirection::Inverse => Direction::Inverse,
                BrowseDirection::Both => Direction::Both,
                BrowseDirection::Invalid => Direction::Both,
            },
        }
    }
}

#[derive(PartialEq, Eq, Hash)]
struct BrowsedNodeRef<'a> {
    id: &'a NodeId,
    direction: Direction,
}

impl Equivalent<BrowsedNode> for BrowsedNodeRef<'_> {
    fn equivalent(&self, key: &BrowsedNode) -> bool {
        self.id == &key.id && self.direction == key.direction
    }
}

struct InnerResultItem {
    it: BrowseResultItem,
    cp: Option<ByteString>,
}

struct BrowseNextItem {
    original: RequestWithRetries,
    cp: ByteString,
}

enum BrowseBatch {
    Browse(Vec<RequestWithRetries>),
    Next(Vec<BrowseNextItem>),
}

async fn run_browse<R: RequestRetryPolicy>(
    session: &Session,
    batch: BrowseBatch,
    policy: R,
    max_references_per_node: u32,
) -> Result<Vec<InnerResultItem>, Error> {
    match batch {
        BrowseBatch::Browse(items) => {
            let r = session
                .send_with_retry(
                    Browse::new(session)
                        .max_references_per_node(max_references_per_node)
                        .nodes_to_browse(items.iter().map(|r| r.request.clone()).collect()),
                    policy,
                )
                .await
                .map_err(|e| Error::new(e, "Browse failed"))?;

            let res = r.results.unwrap_or_default();
            if res.len() != items.len() {
                return Err(Error::new(
                    StatusCode::BadUnexpectedError,
                    format!(
                        "Incorrect number of results returned from Browse, expected {}, got {}",
                        items.len(),
                        res.len()
                    ),
                ));
            }
            Ok(res
                .into_iter()
                .zip(items)
                .map(|(res, it)| InnerResultItem {
                    it: BrowseResultItem {
                        status: res.status_code,
                        request: it,
                        references: res.references.unwrap_or_default(),
                        request_continuation_point: None,
                    },
                    cp: if res.continuation_point.is_null() {
                        None
                    } else {
                        Some(res.continuation_point)
                    },
                })
                .collect())
        }
        BrowseBatch::Next(items) => {
            let r = session
                .send_with_retry(
                    BrowseNext::new(session)
                        .continuation_points(items.iter().map(|r| r.cp.clone()).collect()),
                    policy,
                )
                .await
                .map_err(|e| Error::new(e, "BrowseNext failed"))?;

            let res = r.results.unwrap_or_default();
            if res.len() != items.len() {
                return Err(Error::new(
                    StatusCode::BadUnexpectedError,
                    format!(
                        "Incorrect number of results returned from BrowseNext, expected {}, got {}",
                        items.len(),
                        res.len()
                    ),
                ));
            }
            Ok(res
                .into_iter()
                .zip(items)
                .map(|(res, it)| InnerResultItem {
                    it: BrowseResultItem {
                        status: res.status_code,
                        request: it.original,
                        references: res.references.unwrap_or_default(),
                        request_continuation_point: Some(it.cp),
                    },
                    cp: if res.continuation_point.is_null() {
                        None
                    } else {
                        Some(res.continuation_point)
                    },
                })
                .collect())
        }
    }
}

impl<
        'a,
        T: BrowserPolicy,
        R: RequestRetryPolicy + Clone + 'a,
        TFut: Future<Output = Result<Vec<InnerResultItem>, Error>> + 'a,
    > BrowserExecution<'a, T, R, TFut>
{
    fn visited(&self, dir: Direction, node_id: &NodeId) -> bool {
        self.browsed_nodes.contains(&BrowsedNodeRef {
            id: node_id,
            direction: dir,
        })
    }

    async fn cleanup(&mut self) {
        // First wait for any running browse operations to finish.
        while let Some(r) = self.running_browses.next().await {
            let Ok(r) = r else {
                continue;
            };
            for res in r {
                if let Some(old_cp) = res.it.request_continuation_point.as_ref() {
                    self.pending_continuation_points.remove(old_cp);
                }
                if let Some(cp) = res.cp {
                    self.pending_continuation_points.insert(cp.clone());
                }
            }
        }

        // Chunk-wise free all remaining continuation points.
        let to_consume: Vec<_> = self.pending_continuation_points.drain().collect();
        let mut futures = Vec::new();
        for chunk in to_consume.chunks(self.browser.config.max_nodes_per_request) {
            let session = self.browser.session;
            futures.push(async move {
                // Ignore the result, cleanup is best-effort only.
                let _ = session.browse_next(true, chunk).await;
            });
        }

        // We still want concurrency to make this go quickly if there are a lot of requests.
        let mut it = FuturesUnordered::new();
        loop {
            while it.len() < self.browser.config.max_concurrent_requests
                || self.browser.config.max_concurrent_requests == 0
            {
                let Some(fut) = futures.pop() else {
                    break;
                };
                it.push(fut);
            }

            if it.next().await.is_none() {
                break;
            }
        }
    }

    pub(crate) fn process_result(
        &mut self,
        next: Vec<InnerResultItem>,
    ) -> Result<Vec<BrowseNextItem>, Error> {
        let mut browse_next = Vec::new();
        for res in next {
            // Get the next set of requests from the user-defined policy.
            let to_enqueue = self.browser.handler.get_next(&res.it);
            for mut it in to_enqueue {
                // Check if we have browsed this node before.
                match it.browse_direction {
                    BrowseDirection::Forward => {
                        if self.visited(Direction::Forward, &it.node_id)
                            || self.visited(Direction::Both, &it.node_id)
                        {
                            continue;
                        }
                    }
                    BrowseDirection::Inverse => {
                        if self.visited(Direction::Inverse, &it.node_id)
                            || self.visited(Direction::Both, &it.node_id)
                        {
                            continue;
                        }
                    }
                    BrowseDirection::Both => {
                        if self.visited(Direction::Both, &it.node_id) {
                            continue;
                        }

                        let visited_inv = self.visited(Direction::Inverse, &it.node_id);
                        let visited_for = self.visited(Direction::Forward, &it.node_id);
                        if visited_for && visited_inv {
                            continue;
                        } else if visited_for {
                            it.browse_direction = BrowseDirection::Inverse;
                        } else if visited_inv {
                            it.browse_direction = BrowseDirection::Forward;
                        }
                    }
                    BrowseDirection::Invalid => {
                        return Err(Error::new(
                            StatusCode::BadBrowseDirectionInvalid,
                            "Produced an invalid browse direction",
                        ))
                    }
                }

                // Add the new request to the pending queue.
                self.browsed_nodes.insert(BrowsedNode::from(&it));
                self.pending.push_back(RequestWithRetries {
                    request: it,
                    num_outer_retries: 0,
                    depth: res.it.request.depth + 1,
                });
            }
            // Remove the old continuation point from the pending list, it should have been freed.
            if let Some(old_cp) = res.it.request_continuation_point.as_ref() {
                self.pending_continuation_points.remove(old_cp);
            }
            if let Some(cp) = res.cp {
                // Store the new continuation point in the pending list so that we can
                // free it if we exit early.
                self.pending_continuation_points.insert(cp.clone());
                browse_next.push(BrowseNextItem {
                    original: res.it.request.clone(),
                    cp,
                });
            } else if matches!(res.it.status, StatusCode::BadContinuationPointInvalid)
                && self.browser.config.max_continuation_point_retries
                    > res.it.request.num_outer_retries
            {
                // If we failed with `BadContinuationPointInvalid`, retry from the beginning
                // if configured.
                self.pending.push_back(RequestWithRetries {
                    request: res.it.request.request.clone(),
                    num_outer_retries: res.it.request.num_outer_retries + 1,
                    depth: res.it.request.depth,
                });
            }

            self.pending_out.push_back(res.it);
        }
        Ok(browse_next)
    }
}
