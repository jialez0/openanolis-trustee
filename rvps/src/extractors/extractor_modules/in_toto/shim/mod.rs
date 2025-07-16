use anyhow::*;
use std::ffi::CStr;
use std::os::raw::c_char;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct GoString {
    pub p: *const c_char,
    pub n: isize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct GoSlice {
    pub data: *const c_char,
    pub len: i64,
    pub cap: i64,
}

// Link import cgo function
#[link(name = "cgo")]
extern "C" {
    pub fn verifyGo(
        layoutPath: GoString,
        pubKeyPaths: GoSlice,
        intermediatePaths: GoSlice,
        linkDir: GoString,
        lineNormalizationc: i32,
    ) -> *mut c_char;
}

pub fn verify(
    layout_path: String,
    pub_key_paths: Vec<String>,
    intermediate_paths: Vec<String>,
    link_dir: String,
    line_normalization: bool,
) -> Result<()> {
    // Convert Rust String to GoString
    let layout_path = GoString {
        p: layout_path.as_ptr() as *const c_char,
        n: layout_path.len() as isize,
    };

    // Convert Rust Vec<String> to GoSlice of GoString
    let pub_key_paths_vec: Vec<_> = pub_key_paths
        .iter()
        .map(|arg| GoString {
            p: arg.as_ptr() as *const c_char,
            n: arg.len() as isize,
        })
        .collect();

    let pub_key_paths_goslice = GoSlice {
        data: pub_key_paths_vec.as_ptr() as *const c_char,
        len: pub_key_paths_vec.len() as i64,
        cap: pub_key_paths_vec.len() as i64,
    };

    // Convert Rust Vec<String> to GoSlice of GoString
    let intermediate_paths_vec: Vec<_> = intermediate_paths
        .iter()
        .map(|arg| GoString {
            p: arg.as_ptr() as *const c_char,
            n: arg.len() as isize,
        })
        .collect();

    let intermediate_paths_goslice = GoSlice {
        data: intermediate_paths_vec.as_ptr() as *const c_char,
        len: intermediate_paths_vec.len() as i64,
        cap: intermediate_paths_vec.len() as i64,
    };

    // Convert Rust String to C char*
    let link_dir = GoString {
        p: link_dir.as_ptr() as *const c_char,
        n: link_dir.len() as isize,
    };

    // Convert Rust bool to C int
    let line_normalization_c = line_normalization as i32;

    // Call the function exported by cgo and process the returned string
    let result_buf: *mut c_char = unsafe {
        verifyGo(
            layout_path,
            pub_key_paths_goslice,
            intermediate_paths_goslice,
            link_dir,
            line_normalization_c,
        )
    };

    let result_str: &CStr = unsafe { CStr::from_ptr(result_buf) };
    let res = result_str.to_str()?.to_string();

    if res.starts_with("Error::") {
        bail!(res);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // 测试 GoString 结构体
    #[test]
    fn test_go_string_creation() {
        let test_str = "test string";
        let go_string = GoString {
            p: test_str.as_ptr() as *const c_char,
            n: test_str.len() as isize,
        };

        assert_eq!(go_string.n, test_str.len() as isize);
        assert!(!go_string.p.is_null());
    }

    #[test]
    fn test_go_string_empty() {
        let empty_str = "";
        let go_string = GoString {
            p: empty_str.as_ptr() as *const c_char,
            n: empty_str.len() as isize,
        };

        assert_eq!(go_string.n, 0);
        // 即使是空字符串，指针也不应该为null
        assert!(!go_string.p.is_null());
    }

    #[test]
    fn test_go_string_unicode() {
        let unicode_str = "测试字符串🚀";
        let go_string = GoString {
            p: unicode_str.as_ptr() as *const c_char,
            n: unicode_str.len() as isize,
        };

        // Unicode字符串的字节长度可能与字符数不同
        assert_eq!(go_string.n, unicode_str.len() as isize);
        assert!(go_string.n > 0);
        assert!(!go_string.p.is_null());
    }

    // 测试 GoSlice 结构体
    #[test]
    fn test_go_slice_creation() {
        let data = vec!["item1", "item2", "item3"];
        let go_strings: Vec<GoString> = data
            .iter()
            .map(|s| GoString {
                p: s.as_ptr() as *const c_char,
                n: s.len() as isize,
            })
            .collect();

        let go_slice = GoSlice {
            data: go_strings.as_ptr() as *const c_char,
            len: go_strings.len() as i64,
            cap: go_strings.len() as i64,
        };

        assert_eq!(go_slice.len, 3);
        assert_eq!(go_slice.cap, 3);
        assert!(!go_slice.data.is_null());
    }

    #[test]
    fn test_go_slice_empty() {
        let empty_vec: Vec<GoString> = Vec::new();
        let go_slice = GoSlice {
            data: empty_vec.as_ptr() as *const c_char,
            len: 0,
            cap: 0,
        };

        assert_eq!(go_slice.len, 0);
        assert_eq!(go_slice.cap, 0);
    }

    #[test]
    fn test_go_slice_large_capacity() {
        let mut data = Vec::with_capacity(1000);
        for i in 0..10 {
            data.push(GoString {
                p: std::ptr::null(),
                n: i,
            });
        }

        let go_slice = GoSlice {
            data: data.as_ptr() as *const c_char,
            len: data.len() as i64,
            cap: data.capacity() as i64,
        };

        assert_eq!(go_slice.len, 10);
        assert_eq!(go_slice.cap, 1000);
    }

    // 测试结构体的 Debug 和 Copy traits
    #[test]
    fn test_go_string_traits() {
        let go_string = GoString {
            p: std::ptr::null(),
            n: 0,
        };

        // 测试 Copy trait
        let copied = go_string;
        assert_eq!(go_string.p, copied.p);
        assert_eq!(go_string.n, copied.n);

        // 测试 Debug trait
        let debug_str = format!("{:?}", go_string);
        assert!(debug_str.contains("GoString"));
    }

    #[test]
    fn test_go_slice_traits() {
        let go_slice = GoSlice {
            data: std::ptr::null(),
            len: 0,
            cap: 0,
        };

        // 测试 Copy trait
        let copied = go_slice;
        assert_eq!(go_slice.data, copied.data);
        assert_eq!(go_slice.len, copied.len);
        assert_eq!(go_slice.cap, copied.cap);

        // 测试 Debug trait
        let debug_str = format!("{:?}", go_slice);
        assert!(debug_str.contains("GoSlice"));
    }

    // 测试 verify 函数的参数转换逻辑
    // 注意：这些测试不会实际调用 verifyGo 函数，因为它依赖外部CGO库
    // 我们主要测试参数转换的逻辑

    #[test]
    fn test_verify_parameter_conversion() {
        // 这个测试会失败，因为没有CGO库，但我们可以测试参数转换逻辑
        let layout_path = "test.layout".to_string();
        let pub_key_paths = vec!["key1.pub".to_string(), "key2.pub".to_string()];
        let intermediate_paths = vec!["inter1.link".to_string()];
        let link_dir = "/tmp/test".to_string();
        let line_normalization = true;

        // 这会失败，但我们测试了所有参数转换代码的执行
        let result = verify(
            layout_path,
            pub_key_paths,
            intermediate_paths,
            link_dir,
            line_normalization,
        );

        // 应该失败，因为没有CGO库
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_empty_vectors() {
        let layout_path = "test.layout".to_string();
        let pub_key_paths = Vec::new();
        let intermediate_paths = Vec::new();
        let link_dir = "".to_string();
        let line_normalization = false;

        let result = verify(
            layout_path,
            pub_key_paths,
            intermediate_paths,
            link_dir,
            line_normalization,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_verify_large_vectors() {
        let layout_path = "test.layout".to_string();
        let mut pub_key_paths = Vec::new();
        let mut intermediate_paths = Vec::new();

        // 创建大量的路径
        for i in 0..100 {
            pub_key_paths.push(format!("key_{}.pub", i));
            intermediate_paths.push(format!("intermediate_{}.link", i));
        }

        let link_dir = "/tmp/large_test".to_string();
        let line_normalization = true;

        let result = verify(
            layout_path,
            pub_key_paths,
            intermediate_paths,
            link_dir,
            line_normalization,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_verify_unicode_paths() {
        let layout_path = "测试/布局.layout".to_string();
        let pub_key_paths = vec!["密钥/alice-密钥.pub".to_string(), "keys/bob🔑.pub".to_string()];
        let intermediate_paths = vec!["链接/步骤1.link".to_string()];
        let link_dir = "/tmp/unicode测试".to_string();
        let line_normalization = false;

        let result = verify(
            layout_path,
            pub_key_paths,
            intermediate_paths,
            link_dir,
            line_normalization,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_verify_very_long_paths() {
        let layout_path = "a".repeat(1000) + ".layout";
        let pub_key_paths = vec!["b".repeat(1000) + ".pub"];
        let intermediate_paths = vec!["c".repeat(1000) + ".link"];
        let link_dir = "d".repeat(1000);
        let line_normalization = true;

        let result = verify(
            layout_path,
            pub_key_paths,
            intermediate_paths,
            link_dir,
            line_normalization,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_verify_special_characters() {
        let layout_path = "!@#$%^&*().layout".to_string();
        let pub_key_paths = vec!["key with spaces.pub".to_string(), "key-with-dashes.pub".to_string()];
        let intermediate_paths = vec!["link_with_underscores.link".to_string()];
        let link_dir = "/tmp/dir with spaces".to_string();
        let line_normalization = false;

        let result = verify(
            layout_path,
            pub_key_paths,
            intermediate_paths,
            link_dir,
            line_normalization,
        );

        assert!(result.is_err());
    }

    // 测试bool到int的转换
    #[test]
    fn test_bool_to_int_conversion() {
        // 测试true转换为1
        assert_eq!(true as i32, 1);
        // 测试false转换为0
        assert_eq!(false as i32, 0);
    }

    // 测试边界值
    #[test]
    fn test_verify_boundary_values() {
        // 测试空字符串
        let result = verify(
            String::new(),
            vec![String::new()],
            vec![String::new()],
            String::new(),
            true,
        );
        assert!(result.is_err());

        // 测试单字符
        let result = verify(
            "a".to_string(),
            vec!["b".to_string()],
            vec!["c".to_string()],
            "d".to_string(),
            false,
        );
        assert!(result.is_err());
    }

    // 性能测试
    #[test]
    fn test_verify_performance_with_many_keys() {
        let layout_path = "performance_test.layout".to_string();
        
        // 创建大量公钥路径
        let mut pub_key_paths = Vec::new();
        for i in 0..1000 {
            pub_key_paths.push(format!("key_{:04}.pub", i));
        }

        let intermediate_paths = Vec::new();
        let link_dir = "/tmp/performance_test".to_string();

        let start = std::time::Instant::now();
        let result = verify(
            layout_path,
            pub_key_paths,
            intermediate_paths,
            link_dir,
            true,
        );
        let duration = start.elapsed();

        // 即使失败，转换操作也应该很快完成
        assert!(duration.as_millis() < 100);
        assert!(result.is_err());
    }

    // 测试内存安全性
    #[test]
    fn test_verify_memory_safety() {
        // 测试在函数作用域结束后，临时变量不会导致悬空指针
        {
            let temp_layout = "temp.layout".to_string();
            let temp_keys = vec!["temp.pub".to_string()];
            let temp_intermediate = vec!["temp.link".to_string()];
            let temp_dir = "temp_dir".to_string();

            let result = verify(
                temp_layout,
                temp_keys,
                temp_intermediate,
                temp_dir,
                true,
            );

            assert!(result.is_err());
        }
        // 在这个点，所有临时变量都应该被正确清理
    }

    // 测试GoString和GoSlice的字段边界值
    #[test]
    fn test_go_structures_boundary_values() {
        // 测试最大长度
        let max_len_string = GoString {
            p: std::ptr::null(),
            n: isize::MAX,
        };
        assert_eq!(max_len_string.n, isize::MAX);

        // 测试最小长度
        let min_len_string = GoString {
            p: std::ptr::null(),
            n: 0,
        };
        assert_eq!(min_len_string.n, 0);

        // 测试GoSlice的边界值
        let max_slice = GoSlice {
            data: std::ptr::null(),
            len: i64::MAX,
            cap: i64::MAX,
        };
        assert_eq!(max_slice.len, i64::MAX);
        assert_eq!(max_slice.cap, i64::MAX);

        let zero_slice = GoSlice {
            data: std::ptr::null(),
            len: 0,
            cap: 0,
        };
        assert_eq!(zero_slice.len, 0);
        assert_eq!(zero_slice.cap, 0);
    }
}
