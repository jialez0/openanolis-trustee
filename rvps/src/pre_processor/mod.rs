// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Pre-Processor of RVPS

use std::collections::HashMap;

use anyhow::*;

use super::Message;

/// A Ware loaded in Pre-Processor will process all the messages passing
/// through the Pre-Processor. A series of Wares organized in order can
/// process all the messages in need before they are consumed by the
/// Extractors.
pub trait Ware {
    fn handle(
        &self,
        message: &mut Message,
        context: &mut HashMap<String, String>,
        next: Next<'_>,
    ) -> Result<()>;
}

/// Next encapsulates the remaining ware chain to run in [`Ware::handle`]. You can
/// forward the task down the chain with [`run`].
///
/// [`Ware::handle`]: Ware::handle
/// [`run`]: Self::run
#[derive(Clone)]
pub struct Next<'a> {
    wares: &'a [Box<dyn Ware + Send + Sync>],
}

impl<'a> Next<'a> {
    pub(crate) fn new(wares: &'a [Box<dyn Ware + Send + Sync>]) -> Self {
        Next { wares }
    }

    pub fn run(
        mut self,
        message: &mut Message,
        context: &'a mut HashMap<String, String>,
    ) -> Result<()> {
        if let Some((current, rest)) = self.wares.split_first() {
            self.wares = rest;
            current.handle(message, context, self)
        } else {
            Ok(())
        }
    }
}

/// PreProcessor's interfaces
/// `process` processes the given [`Message`], which contains
/// the provenance information and its type. The process
/// can modify the given [`Message`].
pub trait PreProcessorAPI {
    fn process(&self, message: &mut Message) -> Result<()>;
    fn add_ware(&mut self, ware: Box<dyn Ware + Send + Sync>);
}

#[derive(Default)]
pub struct PreProcessor {
    wares: Vec<Box<dyn Ware + Send + Sync>>,
}

impl PreProcessorAPI for PreProcessor {
    fn process(&self, message: &mut Message) -> Result<()> {
        let mut context = HashMap::new();
        let next = Next::new(&self.wares);
        next.run(message, &mut context)
    }

    fn add_ware(&mut self, ware: Box<dyn Ware + Send + Sync>) {
        self.wares.push(ware);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{anyhow, Result};
    use std::sync::{Arc, Mutex};

    // Mock Ware implementation for testing
    #[derive(Debug)]
    struct MockWare {
        name: String,
        modify_payload: bool,
        should_error: bool,
        execution_log: Arc<Mutex<Vec<String>>>,
    }

    impl MockWare {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                modify_payload: false,
                should_error: false,
                execution_log: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn with_modification(mut self) -> Self {
            self.modify_payload = true;
            self
        }

        fn with_error(mut self) -> Self {
            self.should_error = true;
            self
        }

        fn get_execution_log(&self) -> Vec<String> {
            self.execution_log.lock().unwrap().clone()
        }
    }

    impl Ware for MockWare {
        fn handle(
            &self,
            message: &mut Message,
            context: &mut HashMap<String, String>,
            next: Next<'_>,
        ) -> Result<()> {
            // Log execution
            self.execution_log
                .lock()
                .unwrap()
                .push(format!("Executed: {}", self.name));

            // Add to context
            context.insert(self.name.clone(), "processed".to_string());

            // Modify message if configured
            if self.modify_payload {
                message.payload = format!("{}-modified-by-{}", message.payload, self.name);
            }

            // Return error if configured
            if self.should_error {
                return Err(anyhow!("Error from {}", self.name));
            }

            // Continue with next ware
            next.run(message, context)
        }
    }

    // Helper function to create a test message
    fn create_test_message() -> Message {
        Message {
            version: "0.1.0".to_string(),
            payload: "test-payload".to_string(),
            r#type: "sample".to_string(),
        }
    }

    // Test Next struct
    #[test]
    fn test_next_new() {
        let wares: Vec<Box<dyn Ware + Send + Sync>> = vec![];
        let next = Next::new(&wares);
        
        assert_eq!(next.wares.len(), 0);
    }

    #[test]
    fn test_next_clone() {
        let wares: Vec<Box<dyn Ware + Send + Sync>> = vec![];
        let next = Next::new(&wares);
        let cloned = next.clone();
        
        assert_eq!(next.wares.len(), cloned.wares.len());
        assert_eq!(next.wares.as_ptr(), cloned.wares.as_ptr());
    }

    #[test]
    fn test_next_run_empty_chain() {
        let wares: Vec<Box<dyn Ware + Send + Sync>> = vec![];
        let next = Next::new(&wares);
        let mut message = create_test_message();
        let mut context = HashMap::new();

        let result = next.run(&mut message, &mut context);
        
        assert!(result.is_ok());
        assert_eq!(message.payload, "test-payload"); // Should remain unchanged
        assert!(context.is_empty());
    }

    #[test]
    fn test_next_run_single_ware() {
        let mock_ware = MockWare::new("test-ware");
        let wares: Vec<Box<dyn Ware + Send + Sync>> = vec![Box::new(mock_ware)];
        let next = Next::new(&wares);
        let mut message = create_test_message();
        let mut context = HashMap::new();

        let result = next.run(&mut message, &mut context);
        
        assert!(result.is_ok());
        assert!(context.contains_key("test-ware"));
        assert_eq!(context["test-ware"], "processed");
    }

    #[test]
    fn test_next_run_multiple_wares() {
        let ware1 = MockWare::new("ware1").with_modification();
        let ware2 = MockWare::new("ware2").with_modification();
        let execution_log1 = ware1.execution_log.clone();
        let execution_log2 = ware2.execution_log.clone();
        
        let wares: Vec<Box<dyn Ware + Send + Sync>> = vec![
            Box::new(ware1),
            Box::new(ware2),
        ];
        let next = Next::new(&wares);
        let mut message = create_test_message();
        let mut context = HashMap::new();

        let result = next.run(&mut message, &mut context);
        
        assert!(result.is_ok());
        assert_eq!(message.payload, "test-payload-modified-by-ware1-modified-by-ware2");
        assert!(context.contains_key("ware1"));
        assert!(context.contains_key("ware2"));
        
        // Check execution order
        let log1 = execution_log1.lock().unwrap();
        let log2 = execution_log2.lock().unwrap();
        assert_eq!(log1.len(), 1);
        assert_eq!(log2.len(), 1);
    }

    #[test]
    fn test_next_run_with_error() {
        let ware1 = MockWare::new("ware1");
        let ware2 = MockWare::new("ware2").with_error();
        let ware3 = MockWare::new("ware3");
        
        let wares: Vec<Box<dyn Ware + Send + Sync>> = vec![
            Box::new(ware1),
            Box::new(ware2),
            Box::new(ware3),
        ];
        let next = Next::new(&wares);
        let mut message = create_test_message();
        let mut context = HashMap::new();

        let result = next.run(&mut message, &mut context);
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Error from ware2"));
        
        // Only ware1 and ware2 should have been executed
        assert!(context.contains_key("ware1"));
        assert!(context.contains_key("ware2"));
        assert!(!context.contains_key("ware3"));
    }

    #[test]
    fn test_next_run_split_first_behavior() {
        let ware1 = MockWare::new("first");
        let ware2 = MockWare::new("second");
        let ware3 = MockWare::new("third");
        
        let wares: Vec<Box<dyn Ware + Send + Sync>> = vec![
            Box::new(ware1),
            Box::new(ware2), 
            Box::new(ware3),
        ];
        let next = Next::new(&wares);
        let mut message = create_test_message();
        let mut context = HashMap::new();

        let result = next.run(&mut message, &mut context);
        
        assert!(result.is_ok());
        assert_eq!(context.len(), 3);
        assert!(context.contains_key("first"));
        assert!(context.contains_key("second"));
        assert!(context.contains_key("third"));
    }

    // Test PreProcessor struct
    #[test]
    fn test_preprocessor_default() {
        let processor = PreProcessor::default();
        assert_eq!(processor.wares.len(), 0);
    }

    #[test]
    fn test_preprocessor_add_ware() {
        let mut processor = PreProcessor::default();
        let ware = MockWare::new("test-ware");
        
        processor.add_ware(Box::new(ware));
        
        assert_eq!(processor.wares.len(), 1);
    }

    #[test]
    fn test_preprocessor_add_multiple_wares() {
        let mut processor = PreProcessor::default();
        
        processor.add_ware(Box::new(MockWare::new("ware1")));
        processor.add_ware(Box::new(MockWare::new("ware2")));
        processor.add_ware(Box::new(MockWare::new("ware3")));
        
        assert_eq!(processor.wares.len(), 3);
    }

    #[test]
    fn test_preprocessor_process_empty() {
        let processor = PreProcessor::default();
        let mut message = create_test_message();
        
        let result = processor.process(&mut message);
        
        assert!(result.is_ok());
        assert_eq!(message.payload, "test-payload"); // Should remain unchanged
    }

    #[test]
    fn test_preprocessor_process_single_ware() {
        let mut processor = PreProcessor::default();
        processor.add_ware(Box::new(MockWare::new("single-ware").with_modification()));
        
        let mut message = create_test_message();
        let result = processor.process(&mut message);
        
        assert!(result.is_ok());
        assert_eq!(message.payload, "test-payload-modified-by-single-ware");
    }

    #[test]
    fn test_preprocessor_process_multiple_wares() {
        let mut processor = PreProcessor::default();
        processor.add_ware(Box::new(MockWare::new("first").with_modification()));
        processor.add_ware(Box::new(MockWare::new("second").with_modification()));
        processor.add_ware(Box::new(MockWare::new("third").with_modification()));
        
        let mut message = create_test_message();
        let result = processor.process(&mut message);
        
        assert!(result.is_ok());
        assert_eq!(message.payload, "test-payload-modified-by-first-modified-by-second-modified-by-third");
    }

    #[test]
    fn test_preprocessor_process_with_error() {
        let mut processor = PreProcessor::default();
        processor.add_ware(Box::new(MockWare::new("normal")));
        processor.add_ware(Box::new(MockWare::new("error").with_error()));
        processor.add_ware(Box::new(MockWare::new("never-reached")));
        
        let mut message = create_test_message();
        let result = processor.process(&mut message);
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Error from error"));
    }

    #[test]
    fn test_preprocessor_context_initialization() {
        let mut processor = PreProcessor::default();
        let ware = MockWare::new("context-checker");
        processor.add_ware(Box::new(ware));
        
        let mut message = create_test_message();
        let result = processor.process(&mut message);
        
        assert!(result.is_ok());
        // The context is created fresh for each process call
        // We can't directly inspect it, but we know it starts empty
    }

    // Test Ware trait behavior through MockWare
    #[test]
    fn test_ware_context_modification() {
        let ware = MockWare::new("context-modifier");
        let wares: Vec<Box<dyn Ware + Send + Sync>> = vec![Box::new(ware)];
        let next = Next::new(&wares);
        let mut message = create_test_message();
        let mut context = HashMap::new();
        context.insert("initial".to_string(), "value".to_string());

        let result = next.run(&mut message, &mut context);
        
        assert!(result.is_ok());
        assert_eq!(context.len(), 2); // initial + added by ware
        assert!(context.contains_key("initial"));
        assert!(context.contains_key("context-modifier"));
    }

    #[test]
    fn test_ware_message_modification() {
        let ware = MockWare::new("message-modifier").with_modification();
        let wares: Vec<Box<dyn Ware + Send + Sync>> = vec![Box::new(ware)];
        let next = Next::new(&wares);
        let mut message = create_test_message();
        let mut context = HashMap::new();

        let original_payload = message.payload.clone();
        let result = next.run(&mut message, &mut context);
        
        assert!(result.is_ok());
        assert_ne!(message.payload, original_payload);
        assert!(message.payload.contains("modified-by-message-modifier"));
    }

    // Test edge cases
    #[test]
    fn test_next_with_many_wares() {
        let mut wares: Vec<Box<dyn Ware + Send + Sync>> = Vec::new();
        
        // Create 10 wares
        for i in 0..10 {
            wares.push(Box::new(MockWare::new(&format!("ware{}", i))));
        }
        
        let next = Next::new(&wares);
        let mut message = create_test_message();
        let mut context = HashMap::new();

        let result = next.run(&mut message, &mut context);
        
        assert!(result.is_ok());
        assert_eq!(context.len(), 10);
        
        // Check all wares were executed
        for i in 0..10 {
            assert!(context.contains_key(&format!("ware{}", i)));
        }
    }

    #[test]
    fn test_preprocessor_api_trait_coverage() {
        let mut processor = PreProcessor::default();
        
        // Test through trait interface
        let processor_ref: &mut dyn PreProcessorAPI = &mut processor;
        
        // Add ware through trait
        processor_ref.add_ware(Box::new(MockWare::new("trait-test")));
        
        // Process through trait
        let mut message = create_test_message();
        let result = processor_ref.process(&mut message);
        
        assert!(result.is_ok());
    }

    // Test complex scenarios
    #[test]
    fn test_complex_ware_chain() {
        let mut processor = PreProcessor::default();
        
        // Create a complex chain: modifier -> normal -> modifier -> normal
        processor.add_ware(Box::new(MockWare::new("mod1").with_modification()));
        processor.add_ware(Box::new(MockWare::new("normal1")));
        processor.add_ware(Box::new(MockWare::new("mod2").with_modification()));
        processor.add_ware(Box::new(MockWare::new("normal2")));
        
        let mut message = create_test_message();
        let result = processor.process(&mut message);
        
        assert!(result.is_ok());
        assert_eq!(message.payload, "test-payload-modified-by-mod1-modified-by-mod2");
    }

    #[test]
    fn test_ware_chain_early_termination() {
        let mut processor = PreProcessor::default();
        
        processor.add_ware(Box::new(MockWare::new("first")));
        processor.add_ware(Box::new(MockWare::new("error").with_error()));
        processor.add_ware(Box::new(MockWare::new("unreachable")));
        
        let mut message = create_test_message();
        let result = processor.process(&mut message);
        
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Error from error"));
    }

    // Test memory and ownership
    #[test]
    fn test_next_lifetime_and_borrowing() {
        let ware1 = MockWare::new("lifetime-test1");
        let ware2 = MockWare::new("lifetime-test2");
        
        let wares: Vec<Box<dyn Ware + Send + Sync>> = vec![
            Box::new(ware1),
            Box::new(ware2),
        ];
        
        {
            let next = Next::new(&wares);
            let mut message = create_test_message();
            let mut context = HashMap::new();
            
            let result = next.run(&mut message, &mut context);
            assert!(result.is_ok());
        }
        
        // wares should still be valid here
        assert_eq!(wares.len(), 2);
    }

    #[test]
    fn test_processor_ware_ownership() {
        let mut processor = PreProcessor::default();
        
        {
            let ware = MockWare::new("ownership-test");
            processor.add_ware(Box::new(ware));
        } // ware goes out of scope, but processor owns it
        
        let mut message = create_test_message();
        let result = processor.process(&mut message);
        
        assert!(result.is_ok());
    }
}
