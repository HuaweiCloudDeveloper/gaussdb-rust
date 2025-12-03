//! SCRAM-SHA-256 兼容性集成测试
//!
//! 这些测试验证 GaussDB SCRAM-SHA-256 兼容性修复在真实环境中的工作情况

use tokio_gaussdb::{connect, NoTls, Config};
use std::env;

/// 获取测试连接配置
fn get_test_config() -> Config {
    let host = env::var("GAUSSDB_HOST").unwrap_or_else(|_| "localhost".to_string());
    let port = env::var("GAUSSDB_PORT").unwrap_or_else(|_| "5433".to_string());
    let user = env::var("GAUSSDB_USER").unwrap_or_else(|_| "gaussdb".to_string());
    let password = env::var("GAUSSDB_PASSWORD").unwrap_or_else(|_| "Gaussdb@123".to_string());
    let dbname = env::var("GAUSSDB_DBNAME").unwrap_or_else(|_| "postgres".to_string());

    let mut config = Config::new();
    config.host(&host);
    config.port(port.parse().unwrap_or(5433));
    config.user(&user);
    config.password(&password);
    config.dbname(&dbname);
    config
}

/// 获取测试连接字符串
fn get_test_connection_string() -> String {
    let host = env::var("GAUSSDB_HOST").unwrap_or_else(|_| "localhost".to_string());
    let port = env::var("GAUSSDB_PORT").unwrap_or_else(|_| "5433".to_string());
    let user = env::var("GAUSSDB_USER").unwrap_or_else(|_| "gaussdb".to_string());
    let password = env::var("GAUSSDB_PASSWORD").unwrap_or_else(|_| "Gaussdb@123".to_string());
    let dbname = env::var("GAUSSDB_DBNAME").unwrap_or_else(|_| "postgres".to_string());

    format!("host={} port={} user={} password={} dbname={} sslmode=disable", 
            host, port, user, password, dbname)
}

/// 检查是否有可用的测试数据库
async fn is_test_db_available() -> bool {
    match connect(&get_test_connection_string(), NoTls).await {
        Ok((client, connection)) => {
            tokio::spawn(async move {
                let _ = connection.await;
            });
            
            // 尝试执行简单查询
            match client.query("SELECT 1", &[]).await {
                Ok(_) => true,
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

#[tokio::test]
async fn test_basic_connection() {
    if !is_test_db_available().await {
        println!("跳过测试: 测试数据库不可用");
        return;
    }

    let result = connect(&get_test_connection_string(), NoTls).await;
    assert!(result.is_ok(), "基本连接应该成功");

    let (client, connection) = result.unwrap();
    
    // 启动连接任务
    let conn_handle = tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("连接错误: {}", e);
        }
    });

    // 测试基本查询
    let rows = client.query("SELECT 1 as test_value", &[]).await;
    assert!(rows.is_ok(), "基本查询应该成功");
    
    let rows = rows.unwrap();
    assert_eq!(rows.len(), 1);
    
    let test_value: i32 = rows[0].get(0);
    assert_eq!(test_value, 1);

    // 清理
    conn_handle.abort();
}

#[tokio::test]
async fn test_server_version_query() {
    if !is_test_db_available().await {
        println!("跳过测试: 测试数据库不可用");
        return;
    }

    let (client, connection) = connect(&get_test_connection_string(), NoTls).await.unwrap();
    
    let conn_handle = tokio::spawn(async move {
        let _ = connection.await;
    });

    // 查询服务器版本
    let rows = client.query("SELECT version()", &[]).await;
    assert!(rows.is_ok(), "版本查询应该成功");
    
    let rows = rows.unwrap();
    assert_eq!(rows.len(), 1);
    
    let version: String = rows[0].get(0);
    assert!(!version.is_empty(), "版本字符串不应为空");
    
    // 验证是 GaussDB/openGauss
    assert!(
        version.contains("openGauss") || version.contains("GaussDB"),
        "应该是 GaussDB/openGauss 服务器，实际版本: {}",
        version
    );

    conn_handle.abort();
}

#[tokio::test]
async fn test_concurrent_connections() {
    if !is_test_db_available().await {
        println!("跳过测试: 测试数据库不可用");
        return;
    }

    let conn_str = get_test_connection_string();
    let mut handles = Vec::new();

    // 创建 3 个并发连接
    for i in 1..=3 {
        let conn_str_clone = conn_str.clone();
        let handle = tokio::spawn(async move {
            let result = connect(&conn_str_clone, NoTls).await;
            match result {
                Ok((client, connection)) => {
                    let conn_handle = tokio::spawn(async move {
                        let _ = connection.await;
                    });

                    let query_result = client.query("SELECT $1::int as connection_id", &[&i]).await;
                    conn_handle.abort();
                    
                    match query_result {
                        Ok(rows) => {
                            if let Some(row) = rows.first() {
                                let id: i32 = row.get(0);
                                Ok(id)
                            } else {
                                Err("查询无结果".to_string())
                            }
                        }
                        Err(e) => Err(format!("查询失败: {}", e))
                    }
                }
                Err(e) => Err(format!("连接失败: {}", e))
            }
        });
        handles.push(handle);
    }

    // 等待所有连接完成
    let mut success_count = 0;
    for (i, handle) in handles.into_iter().enumerate() {
        match handle.await {
            Ok(Ok(connection_id)) => {
                assert_eq!(connection_id, (i + 1) as i32);
                success_count += 1;
            }
            Ok(Err(e)) => panic!("连接 {} 失败: {}", i + 1, e),
            Err(e) => panic!("任务 {} 执行失败: {}", i + 1, e),
        }
    }

    assert_eq!(success_count, 3, "所有并发连接都应该成功");
}

#[tokio::test]
async fn test_transaction_support() {
    if !is_test_db_available().await {
        println!("跳过测试: 测试数据库不可用");
        return;
    }

    let (mut client, connection) = connect(&get_test_connection_string(), NoTls).await.unwrap();
    
    let conn_handle = tokio::spawn(async move {
        let _ = connection.await;
    });

    // 开始事务
    let transaction = client.transaction().await;
    assert!(transaction.is_ok(), "事务开始应该成功");
    
    let transaction = transaction.unwrap();

    // 在事务中执行查询
    let rows = transaction.query("SELECT 'transaction_test' as test_msg", &[]).await;
    assert!(rows.is_ok(), "事务中的查询应该成功");
    
    let rows = rows.unwrap();
    assert_eq!(rows.len(), 1);
    
    let test_msg: String = rows[0].get(0);
    assert_eq!(test_msg, "transaction_test");

    // 提交事务
    let commit_result = transaction.commit().await;
    assert!(commit_result.is_ok(), "事务提交应该成功");

    conn_handle.abort();
}

#[tokio::test]
async fn test_prepared_statements() {
    if !is_test_db_available().await {
        println!("跳过测试: 测试数据库不可用");
        return;
    }

    let (client, connection) = connect(&get_test_connection_string(), NoTls).await.unwrap();
    
    let conn_handle = tokio::spawn(async move {
        let _ = connection.await;
    });

    // 准备语句
    let stmt = client.prepare("SELECT $1::int + $2::int as sum").await;
    assert!(stmt.is_ok(), "准备语句应该成功");
    
    let stmt = stmt.unwrap();

    // 执行准备语句
    let rows = client.query(&stmt, &[&10i32, &20i32]).await;
    assert!(rows.is_ok(), "执行准备语句应该成功");
    
    let rows = rows.unwrap();
    assert_eq!(rows.len(), 1);
    
    let sum: i32 = rows[0].get(0);
    assert_eq!(sum, 30);

    conn_handle.abort();
}

#[tokio::test]
async fn test_error_handling() {
    if !is_test_db_available().await {
        println!("跳过测试: 测试数据库不可用");
        return;
    }

    let (client, connection) = connect(&get_test_connection_string(), NoTls).await.unwrap();
    
    let conn_handle = tokio::spawn(async move {
        let _ = connection.await;
    });

    // 执行无效的 SQL
    let result = client.query("SELECT * FROM non_existent_table", &[]).await;
    assert!(result.is_err(), "无效查询应该失败");

    // 验证错误类型
    match result {
        Err(e) => {
            let error_str = format!("{}", e);
            assert!(
                error_str.contains("relation") || error_str.contains("table") || error_str.contains("exist"),
                "错误消息应该包含表不存在的信息: {}",
                error_str
            );
        }
        Ok(_) => panic!("无效查询不应该成功"),
    }

    conn_handle.abort();
}

#[tokio::test]
async fn test_config_builder() {
    if !is_test_db_available().await {
        println!("跳过测试: 测试数据库不可用");
        return;
    }

    let config = get_test_config();
    let result = config.connect(NoTls).await;
    assert!(result.is_ok(), "Config 构建器连接应该成功");

    let (client, connection) = result.unwrap();
    
    let conn_handle = tokio::spawn(async move {
        let _ = connection.await;
    });

    // 测试查询
    let rows = client.query("SELECT current_database()", &[]).await;
    assert!(rows.is_ok(), "数据库名查询应该成功");
    
    let rows = rows.unwrap();
    assert_eq!(rows.len(), 1);
    
    let db_name: String = rows[0].get(0);
    assert!(!db_name.is_empty(), "数据库名不应为空");

    conn_handle.abort();
}
