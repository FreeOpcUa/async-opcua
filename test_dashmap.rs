use dashmap::DashMap;

fn main() {
    let map: DashMap<i32, i32> = DashMap::new();
    let _ = map.get(&1);
    let _ = map.get_mut(&1);
}
