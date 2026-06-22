//! Typed adapters for registering OPC UA method callbacks.
//!
//! The existing method callback path accepts raw [`Variant`] arguments and
//! returns raw [`Variant`] outputs. This module adds an opt-in typed layer over
//! that path, so method authors can decode arguments through
//! [`TryFromVariant`] and return output tuples that are converted back into
//! variants.
//!
//! A single output value is represented as a one-element tuple, for example
//! `(value,)`. Returning `()` produces no output arguments.
//!
//! This adapter reports argument decoding failures as the operation-level
//! [`StatusCode`]. It does not populate the wire per-argument
//! `inputArgumentResults` vector because the callback registration path carries
//! only a single operation status.

use opcua_types::{StatusCode, TryFromVariant, Variant};

use super::RequestContext;

/// Converts a raw method argument into a typed Rust value.
///
/// Any type implementing [`TryFromVariant`] can be used as a typed method
/// argument.
pub trait MethodArg: Sized {
    /// Converts one raw method argument into `Self`.
    ///
    /// # Errors
    ///
    /// Returns a [`StatusCode`] when the raw [`Variant`] cannot be converted.
    fn from_method_arg(v: Variant) -> Result<Self, StatusCode>;
}

impl<T> MethodArg for T
where
    T: TryFromVariant,
{
    fn from_method_arg(v: Variant) -> Result<Self, StatusCode> {
        T::try_from_variant(v).map_err(StatusCode::from)
    }
}

/// Converts a typed method return value into OPC UA method output arguments.
///
/// This trait is implemented only for tuples. Use `(value,)` for one output
/// argument and `()` for no output arguments.
pub trait IntoMethodOutputs {
    /// Converts `self` into the raw method output arguments.
    fn into_method_outputs(self) -> Vec<Variant>;
}

impl IntoMethodOutputs for () {
    fn into_method_outputs(self) -> Vec<Variant> {
        Vec::new()
    }
}

macro_rules! impl_into_method_outputs {
    ($($tp:ident),+) => {
        impl<$($tp),+> IntoMethodOutputs for ($($tp,)+)
        where
            $($tp: Into<Variant>),+
        {
            #[allow(non_snake_case)]
            fn into_method_outputs(self) -> Vec<Variant> {
                let ($($tp,)+) = self;
                vec![$($tp.into()),+]
            }
        }
    };
}

impl_into_method_outputs!(A);
impl_into_method_outputs!(A, B);
impl_into_method_outputs!(A, B, C);
impl_into_method_outputs!(A, B, C, D);
impl_into_method_outputs!(A, B, C, D, E);
impl_into_method_outputs!(A, B, C, D, E, F);

/// Handles typed method calls without request context.
///
/// Implementations are provided for closures and function pointers with zero
/// through six typed arguments.
pub trait MethodHandler<Args> {
    /// Handles one method call using raw OPC UA argument values.
    ///
    /// # Errors
    ///
    /// Returns an operation-level [`StatusCode`] when the argument count is
    /// incorrect, argument decoding fails, or the wrapped handler returns an
    /// error.
    fn handle(&self, args: &[Variant]) -> Result<Vec<Variant>, StatusCode>;
}

/// Handles typed method calls with request context.
///
/// Implementations are provided for closures and function pointers with zero
/// through six typed arguments after the leading [`RequestContext`] reference.
pub trait MethodHandlerWithContext<Args> {
    /// Handles one method call using the request context and raw OPC UA
    /// argument values.
    ///
    /// # Errors
    ///
    /// Returns an operation-level [`StatusCode`] when the argument count is
    /// incorrect, argument decoding fails, or the wrapped handler returns an
    /// error.
    fn handle(&self, ctx: &RequestContext, args: &[Variant]) -> Result<Vec<Variant>, StatusCode>;
}

fn check_arg_count(args: &[Variant], expected: usize) -> Result<(), StatusCode> {
    if args.len() < expected {
        return Err(StatusCode::BadArgumentsMissing);
    }
    if args.len() > expected {
        return Err(StatusCode::BadTooManyArguments);
    }
    Ok(())
}

macro_rules! impl_method_handler {
    (($($tp:ident),*) => ($($var:ident: $idx:tt),*)) => {
        impl<Handler, Output, HandlerError, $($tp,)*> MethodHandler<($($tp,)*)> for Handler
        where
            Handler: Fn($($tp),*) -> Result<Output, HandlerError>,
            Output: IntoMethodOutputs,
            HandlerError: Into<StatusCode>,
            $($tp: MethodArg,)*
        {
            fn handle(&self, args: &[Variant]) -> Result<Vec<Variant>, StatusCode> {
                const ARG_COUNT: usize = 0 $(+ {
                    let _ = stringify!($tp);
                    1
                })*;

                check_arg_count(args, ARG_COUNT)?;

                $(
                    let $var = $tp::from_method_arg(args[$idx].clone())
                        .map_err(|_| StatusCode::BadInvalidArgument)?;
                )*

                match self($($var),*) {
                    Ok(out) => Ok(out.into_method_outputs()),
                    Err(err) => Err(err.into()),
                }
            }
        }
    };
}

macro_rules! impl_method_handler_with_context {
    (($($tp:ident),*) => ($($var:ident: $idx:tt),*)) => {
        impl<Handler, Output, HandlerError, $($tp,)*> MethodHandlerWithContext<($($tp,)*)> for Handler
        where
            Handler: for<'ctx> Fn(&'ctx RequestContext, $($tp),*) -> Result<Output, HandlerError>,
            Output: IntoMethodOutputs,
            HandlerError: Into<StatusCode>,
            $($tp: MethodArg,)*
        {
            fn handle(
                &self,
                ctx: &RequestContext,
                args: &[Variant],
            ) -> Result<Vec<Variant>, StatusCode> {
                const ARG_COUNT: usize = 0 $(+ {
                    let _ = stringify!($tp);
                    1
                })*;

                check_arg_count(args, ARG_COUNT)?;

                $(
                    let $var = $tp::from_method_arg(args[$idx].clone())
                        .map_err(|_| StatusCode::BadInvalidArgument)?;
                )*

                match self(ctx, $($var),*) {
                    Ok(out) => Ok(out.into_method_outputs()),
                    Err(err) => Err(err.into()),
                }
            }
        }
    };
}

impl_method_handler!(() => ());
impl_method_handler!((A) => (a: 0));
impl_method_handler!((A, B) => (a: 0, b: 1));
impl_method_handler!((A, B, C) => (a: 0, b: 1, c: 2));
impl_method_handler!((A, B, C, D) => (a: 0, b: 1, c: 2, d: 3));
impl_method_handler!((A, B, C, D, E) => (a: 0, b: 1, c: 2, d: 3, e: 4));
impl_method_handler!((A, B, C, D, E, F) => (a: 0, b: 1, c: 2, d: 3, e: 4, f: 5));

impl_method_handler_with_context!(() => ());
impl_method_handler_with_context!((A) => (a: 0));
impl_method_handler_with_context!((A, B) => (a: 0, b: 1));
impl_method_handler_with_context!((A, B, C) => (a: 0, b: 1, c: 2));
impl_method_handler_with_context!((A, B, C, D) => (a: 0, b: 1, c: 2, d: 3));
impl_method_handler_with_context!((A, B, C, D, E) => (a: 0, b: 1, c: 2, d: 3, e: 4));
impl_method_handler_with_context!((A, B, C, D, E, F) => (a: 0, b: 1, c: 2, d: 3, e: 4, f: 5));

/// Adapts a typed method handler to the raw method callback signature.
///
/// # Examples
///
/// ```ignore
/// use async_opcua_server::node_manager::typed_method;
/// use opcua_types::StatusCode;
///
/// manager.inner().add_method_callback(
///     id,
///     typed_method(|name: String, count: i32| -> Result<(String,), StatusCode> {
///         Ok((format!("{name}:{count}"),))
///     }),
/// );
/// ```
pub fn typed_method<F, Args>(
    f: F,
) -> impl Fn(&[Variant]) -> Result<Vec<Variant>, StatusCode> + Send + Sync + 'static
where
    F: MethodHandler<Args> + Send + Sync + 'static,
    Args: 'static,
{
    move |args| f.handle(args)
}

/// Adapts a typed method handler with request context to the raw method
/// callback signature.
pub fn typed_method_with_context<F, Args>(
    f: F,
) -> impl Fn(&RequestContext, &[Variant]) -> Result<Vec<Variant>, StatusCode> + Send + Sync + 'static
where
    F: MethodHandlerWithContext<Args> + Send + Sync + 'static,
    Args: 'static,
{
    move |ctx, args| f.handle(ctx, args)
}

#[cfg(test)]
mod tests {
    //! Independent verification (feature 021) — anchored to OPC UA Part 4 Call-service status-code
    //! semantics and real `Variant` round-trips, NOT to the implementation's own helpers. Authored
    //! separately from the adapter under the project's verification division.
    use super::{typed_method, IntoMethodOutputs};
    use opcua_types::{Error, StatusCode, Variant};

    // --- IntoMethodOutputs: marshaling per arity (real Into<Variant>) ---

    #[test]
    fn outputs_zero_one_and_multi_arity() {
        assert_eq!(().into_method_outputs(), Vec::<Variant>::new());
        assert_eq!(
            (42i32,).into_method_outputs(),
            vec![Variant::from(42i32)],
            "single output is a 1-tuple"
        );
        assert_eq!(
            (1i32, "x".to_string(), true).into_method_outputs(),
            vec![Variant::from(1i32), Variant::from("x"), Variant::from(true)],
            "multi-output marshals positionally"
        );
        // arity 6 (the macro's upper bound)
        let six = (1i32, 2i32, 3i32, 4i32, 5i32, 6i32).into_method_outputs();
        assert_eq!(six.len(), 6);
    }

    // --- valid calls: decode -> invoke -> marshal ---

    #[test]
    fn valid_call_decodes_args_and_marshals_outputs() {
        let m = typed_method(
            |name: String, count: i32| -> Result<(String,), StatusCode> {
                Ok((format!("{name}:{count}"),))
            },
        );
        let out = m(&[Variant::from("hi"), Variant::from(3i32)]).expect("valid call succeeds");
        assert_eq!(out, vec![Variant::from("hi:3".to_string())]);
    }

    #[test]
    fn zero_in_zero_out_call() {
        let m = typed_method(|| -> Result<(), StatusCode> { Ok(()) });
        assert_eq!(m(&[]).expect("ok"), Vec::<Variant>::new());
    }

    #[test]
    fn multi_output_call() {
        let m = typed_method(|a: i32, b: i32| -> Result<(i32, String), StatusCode> {
            Ok((a + b, format!("{a}+{b}")))
        });
        let out = m(&[Variant::from(2i32), Variant::from(5i32)]).expect("ok");
        assert_eq!(
            out,
            vec![Variant::from(7i32), Variant::from("2+5".to_string())]
        );
    }

    #[test]
    fn decodes_each_common_arg_type() {
        // bool, f64, String, i32 all decode through TryFromVariant via MethodArg
        let m = typed_method(
            |b: bool, f: f64, s: String, i: i32| -> Result<(bool,), StatusCode> {
                Ok((b && f > 0.0 && !s.is_empty() && i != 0,))
            },
        );
        let out = m(&[
            Variant::from(true),
            Variant::from(1.5f64),
            Variant::from("ok"),
            Variant::from(7i32),
        ])
        .expect("ok");
        assert_eq!(out, vec![Variant::from(true)]);
    }

    // --- Part 4 Call-service status codes on bad input (the conformance contract) ---

    #[test]
    fn too_few_arguments_is_bad_arguments_missing() {
        let m = typed_method(|_a: i32, _b: i32| -> Result<(), StatusCode> { Ok(()) });
        assert_eq!(
            m(&[Variant::from(1i32)]).unwrap_err(),
            StatusCode::BadArgumentsMissing
        );
        assert_eq!(m(&[]).unwrap_err(), StatusCode::BadArgumentsMissing);
    }

    #[test]
    fn too_many_arguments_is_bad_too_many_arguments() {
        let m = typed_method(|_a: i32| -> Result<(), StatusCode> { Ok(()) });
        assert_eq!(
            m(&[Variant::from(1i32), Variant::from(2i32)]).unwrap_err(),
            StatusCode::BadTooManyArguments
        );
    }

    #[test]
    fn undecodable_argument_is_bad_invalid_argument() {
        // A method expecting a bool, given a non-boolean string that cannot cast to Boolean.
        let m = typed_method(|_b: bool| -> Result<(), StatusCode> { Ok(()) });
        assert_eq!(
            m(&[Variant::from("not-a-bool")]).unwrap_err(),
            StatusCode::BadInvalidArgument
        );
    }

    // --- user error surfaces (E: Into<StatusCode>) for both StatusCode and Error ---

    #[test]
    fn user_statuscode_error_surfaces() {
        let m =
            typed_method(|_a: i32| -> Result<(), StatusCode> { Err(StatusCode::BadNotSupported) });
        assert_eq!(
            m(&[Variant::from(1i32)]).unwrap_err(),
            StatusCode::BadNotSupported
        );
    }

    #[test]
    fn user_error_type_surfaces_its_status() {
        let m = typed_method(|_a: i32| -> Result<(), Error> {
            Err(Error::new(StatusCode::BadOutOfRange, "out of range"))
        });
        assert_eq!(
            m(&[Variant::from(1i32)]).unwrap_err(),
            StatusCode::BadOutOfRange
        );
    }

    // --- no panic on adversarial input (Constitution IV) ---

    #[test]
    fn never_panics_on_bad_arity_or_type() {
        let m = typed_method(|_a: i32, _b: String| -> Result<(i32,), StatusCode> { Ok((0,)) });
        assert!(m(&[]).is_err());
        assert!(m(&[Variant::from(1i32)]).is_err());
        assert!(m(&[Variant::from(1i32), Variant::from("s"), Variant::from(9i32)]).is_err());
        assert!(m(&[Variant::from(1i32), Variant::from("s")]).is_ok());
    }
}
