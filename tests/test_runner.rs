// Custom test harness with progress bar and compact output
use std::io::{self, Write};
use std::time::Instant;

pub struct TestRunner {
    total: usize,
    passed: usize,
    failed: usize,
    failures: Vec<(String, String)>,
    start_time: Instant,
}

impl TestRunner {
    pub fn new(total: usize) -> Self {
        Self {
            total,
            passed: 0,
            failed: 0,
            failures: Vec::new(),
            start_time: Instant::now(),
        }
    }
    
    pub fn run_test<F>(&mut self, name: &str, test_fn: F)
    where
        F: FnOnce() + std::panic::UnwindSafe,
    {
        let result = std::panic::catch_unwind(test_fn);
        
        match result {
            Ok(_) => {
                self.passed += 1;
                self.print_progress(true);
            }
            Err(err) => {
                self.failed += 1;
                let error_msg = if let Some(s) = err.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = err.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "Test panicked".to_string()
                };
                self.failures.push((name.to_string(), error_msg));
                self.print_progress(false);
            }
        }
    }
    
    fn print_progress(&self, success: bool) {
        let completed = self.passed + self.failed;
        let progress = (completed as f64 / self.total as f64 * 50.0) as usize;
        
        print!("\r[");
        for i in 0..50 {
            if i < progress {
                if success {
                    print!("=");
                } else {
                    print!("x");
                }
            } else if i == progress {
                print!(">");
            } else {
                print!(" ");
            }
        }
        print!("] {}/{} ", completed, self.total);
        io::stdout().flush().unwrap();
    }
    
    pub fn finish(&self) {
        println!("\n");
        let duration = self.start_time.elapsed();
        
        if self.failed == 0 {
            println!("✓ All {} tests passed in {:.2}s", self.total, duration.as_secs_f64());
        } else {
            println!("✗ {} tests failed, {} passed in {:.2}s\n", self.failed, self.passed, duration.as_secs_f64());
            
            for (name, error) in &self.failures {
                println!("FAILED: {}", name);
                println!("  {}\n", error);
            }
        }
    }
    
    pub fn has_failures(&self) -> bool {
        self.failed > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_runner_creation() {
        let runner = TestRunner::new(10);
        assert_eq!(runner.total, 10);
        assert_eq!(runner.passed, 0);
        assert_eq!(runner.failed, 0);
    }
    
    #[test]
    fn test_successful_test() {
        let mut runner = TestRunner::new(1);
        runner.run_test("test", || {
            assert_eq!(1 + 1, 2);
        });
        assert_eq!(runner.passed, 1);
        assert_eq!(runner.failed, 0);
    }
    
    #[test]
    fn test_failed_test() {
        let mut runner = TestRunner::new(1);
        runner.run_test("test", || {
            panic!("Test failed");
        });
        assert_eq!(runner.passed, 0);
        assert_eq!(runner.failed, 1);
        assert!(!runner.failures.is_empty());
    }
}
