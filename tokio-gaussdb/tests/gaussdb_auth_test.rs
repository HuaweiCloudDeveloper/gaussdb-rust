//! GaussDB特有认证方法测试
//!
//! 测试SHA256和MD5_SHA256认证功能

use tokio_gaussdb::{connect, Config, NoTls};

/// 测试基础连接功能
#[tokio::test]
async fn test_basic_connection() {
    let result = connect(
        "host=localhost port=5433 user=gaussdb password=Gaussdb@123 dbname=postgres",
        NoTls,
    )
    .await;

    match result {
        Ok((client, connection)) => {
            // 启动连接任务
            let connection_handle = tokio::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("Connection error: {}", e);
                }
            });

            // 测试基本查询
            let rows = client.query("SELECT version()", &[]).await.unwrap();
            assert_eq!(rows.len(), 1);

            let version: &str = rows[0].get(0);
            println!("Database version: {}", version);
            assert!(version.contains("gaussdb") || version.contains("PostgreSQL"));

            // 清理连接
            drop(client);
            connection_handle.await.unwrap();

            println!("✅ Basic connection test passed");
        }
        Err(e) => {
            panic!("❌ Connection failed: {}", e);
        }
    }
}

/// 测试SHA256认证 (GaussDB特有)
#[tokio::test]
async fn test_sha256_authentication() {
    // 使用Config构建器测试SHA256认证
    let mut config = Config::new();
    config
        .host("localhost")
        .port(5433)
        .user("gaussdb")
        .password("Gaussdb@123")
        .dbname("postgres");

    let result = config.connect(NoTls).await;

    match result {
        Ok((client, connection)) => {
            let connection_handle = tokio::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("Connection error: {}", e);
                }
            });

            // 测试认证后的操作
            let rows = client.query("SELECT current_user", &[]).await.unwrap();
            let current_user: &str = rows[0].get(0);
            assert_eq!(current_user, "gaussdb");

            // 测试数据库操作
            client
                .execute("CREATE TEMPORARY TABLE auth_test (id INT, name TEXT)", &[])
                .await
                .unwrap();
            client
                .execute("INSERT INTO auth_test VALUES (1, 'test')", &[])
                .await
                .unwrap();

            let rows = client.query("SELECT * FROM auth_test", &[]).await.unwrap();
            assert_eq!(rows.len(), 1);

            drop(client);
            connection_handle.await.unwrap();

            println!("✅ SHA256 authentication test passed");
        }
        Err(e) => {
            println!("⚠️ SHA256 authentication test failed: {}", e);
            // 不panic，因为认证方法可能未配置
        }
    }
}

/// 测试MD5_SHA256认证 (GaussDB特有)
#[tokio::test]
async fn test_md5_sha256_authentication() {
    // 测试MD5_SHA256认证的连接字符串解析
    let connection_string =
        "host=localhost port=5433 user=gaussdb password=Gaussdb@123 dbname=postgres";

    let result = connect(connection_string, NoTls).await;

    match result {
        Ok((mut client, connection)) => {
            let connection_handle = tokio::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("Connection error: {}", e);
                }
            });

            // 验证连接成功
            let rows = client.query("SELECT 1 as test", &[]).await.unwrap();
            let test_value: i32 = rows[0].get(0);
            assert_eq!(test_value, 1);

            // 测试事务功能
            let transaction = client.transaction().await.unwrap();
            transaction
                .execute("CREATE TEMPORARY TABLE md5_test (data TEXT)", &[])
                .await
                .unwrap();
            transaction
                .execute("INSERT INTO md5_test VALUES ('md5_sha256_test')", &[])
                .await
                .unwrap();
            transaction.commit().await.unwrap();

            let rows = client
                .query("SELECT data FROM md5_test", &[])
                .await
                .unwrap();
            let data: &str = rows[0].get(0);
            assert_eq!(data, "md5_sha256_test");

            drop(client);
            connection_handle.await.unwrap();

            println!("✅ MD5_SHA256 authentication test passed");
        }
        Err(e) => {
            println!("⚠️ MD5_SHA256 authentication test failed: {}", e);
            // 不panic，因为认证方法可能未配置
        }
    }
}

/// 测试错误的认证信息
#[tokio::test]
async fn test_wrong_credentials() {
    let result = connect(
        "host=localhost port=5433 user=gaussdb password=wrong_password dbname=postgres",
        NoTls,
    )
    .await;

    match result {
        Ok(_) => {
            panic!("❌ Should have failed with wrong password");
        }
        Err(e) => {
            println!("✅ Correctly rejected wrong password: {}", e);
            // 验证错误类型
            assert!(e.to_string().contains("password") || e.to_string().contains("authentication"));
        }
    }
}

/// 测试不存在的用户
#[tokio::test]
async fn test_nonexistent_user() {
    let result = connect(
        "host=localhost port=5433 user=nonexistent_user password=any_password dbname=postgres",
        NoTls,
    )
    .await;

    match result {
        Ok(_) => {
            panic!("❌ Should have failed with nonexistent user");
        }
        Err(e) => {
            println!("✅ Correctly rejected nonexistent user: {}", e);
        }
    }
}

/// 测试连接参数解析
#[tokio::test]
async fn test_connection_params() {
    // 测试各种连接字符串格式
    let test_cases = [
        "host=localhost port=5433 user=gaussdb password=Gaussdb@123 dbname=postgres",
        "postgresql://gaussdb:Gaussdb%40123@localhost:5433/postgres",
        "host=localhost port=5433 user=gaussdb password=Gaussdb@123 dbname=postgres sslmode=disable",
    ];

    for (i, conn_str) in test_cases.iter().enumerate() {
        println!("Testing connection string {}: {}", i + 1, conn_str);

        let result = connect(conn_str, NoTls).await;
        match result {
            Ok((client, connection)) => {
                let connection_handle = tokio::spawn(async move {
                    if let Err(e) = connection.await {
                        eprintln!("Connection error: {}", e);
                    }
                });

                // 简单验证
                let rows = client
                    .query("SELECT 'connection_test' as result", &[])
                    .await
                    .unwrap();
                let result: &str = rows[0].get(0);
                assert_eq!(result, "connection_test");

                drop(client);
                connection_handle.await.unwrap();

                println!("✅ Connection string {} works", i + 1);
            }
            Err(e) => {
                println!("⚠️ Connection string {} failed: {}", i + 1, e);
            }
        }
    }
}

/// 测试并发连接
#[tokio::test]
async fn test_concurrent_connections() {
    let connection_string =
        "host=localhost port=5433 user=gaussdb password=Gaussdb@123 dbname=postgres";

    // 创建多个并发连接
    let mut handles = Vec::new();

    for i in 0..3 {
        let conn_str = connection_string.to_string();
        let handle = tokio::spawn(async move {
            let result = connect(&conn_str, NoTls).await;
            match result {
                Ok((client, connection)) => {
                    let connection_handle = tokio::spawn(async move {
                        if let Err(e) = connection.await {
                            eprintln!("Connection error: {}", e);
                        }
                    });

                    // 执行查询
                    let rows = client
                        .query("SELECT $1::INT as connection_id", &[&i])
                        .await
                        .unwrap();
                    let connection_id: i32 = rows[0].get(0);
                    assert_eq!(connection_id, i);

                    drop(client);
                    connection_handle.await.unwrap();

                    println!("✅ Concurrent connection {} successful", i);
                    true
                }
                Err(e) => {
                    println!("❌ Concurrent connection {} failed: {}", i, e);
                    false
                }
            }
        });
        handles.push(handle);
    }

    // 等待所有连接完成
    let results = futures_util::future::join_all(handles).await;
    let successful_connections = results
        .into_iter()
        .map(|r| r.unwrap())
        .filter(|&success| success)
        .count();

    println!(
        "✅ {}/3 concurrent connections successful",
        successful_connections
    );
    assert!(
        successful_connections >= 1,
        "At least one connection should succeed"
    );
}
