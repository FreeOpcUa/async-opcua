use crate::{RequestMessage, ResponseMessage};

#[test]
fn size() {
    // This test just gets the byte size of ResponseMessage and RequestMessage to ensure they
    // are not too big.
    use std::mem;
    let size = mem::size_of::<ResponseMessage>();
    println!("ResponseMessage size = {size}");
    assert!(size <= 16);

    let size = mem::size_of::<RequestMessage>();
    println!("ResponseMessage size = {size}");
    assert!(size <= 16);
}
