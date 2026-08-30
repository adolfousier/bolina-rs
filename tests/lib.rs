//! Global test timeout using ntest.

use ntest::timeout;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    #[timeout(5000)]
    fn global_timeout_test() {
        // This test should complete within 5 seconds
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}
