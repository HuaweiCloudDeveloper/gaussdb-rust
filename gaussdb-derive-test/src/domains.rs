use crate::test_type;
use gaussdb::{Client, NoTls};
use gaussdb_types::{FromSql, ToSql, WrongType};
use gaussdb_test_helpers::*;
use std::error::Error;

#[test]
#[ignore] // GaussDB doesn't support DOMAIN
fn defaults() {
    #[derive(FromSql, ToSql, Debug, PartialEq)]
    struct SessionId(Vec<u8>);

    let mut conn = Client::connect(
        &get_test_conn_str(),
        NoTls,
    )
    .unwrap();
    conn.execute(
        "CREATE DOMAIN pg_temp.\"SessionId\" AS bytea CHECK(octet_length(VALUE) = 16);",
        &[],
    )
    .unwrap();

    test_type(
        &mut conn,
        "\"SessionId\"",
        &[(
            SessionId(b"0123456789abcdef".to_vec()),
            "'0123456789abcdef'",
        )],
    );
}

#[test]
#[ignore] // GaussDB doesn't support DOMAIN
fn name_overrides() {
    #[derive(FromSql, ToSql, Debug, PartialEq)]
    #[gaussdb(name = "session_id")]
    struct SessionId(Vec<u8>);

    let mut conn = Client::connect(
        &get_test_conn_str(),
        NoTls,
    )
    .unwrap();
    conn.execute(
        "CREATE DOMAIN pg_temp.session_id AS bytea CHECK(octet_length(VALUE) = 16);",
        &[],
    )
    .unwrap();

    test_type(
        &mut conn,
        "session_id",
        &[(
            SessionId(b"0123456789abcdef".to_vec()),
            "'0123456789abcdef'",
        )],
    );
}

#[test]
#[ignore] // GaussDB doesn't support DOMAIN
fn wrong_name() {
    #[derive(FromSql, ToSql, Debug, PartialEq)]
    struct SessionId(Vec<u8>);

    let mut conn = Client::connect(
        &get_test_conn_str(),
        NoTls,
    )
    .unwrap();
    conn.execute(
        "CREATE DOMAIN pg_temp.session_id AS bytea CHECK(octet_length(VALUE) = 16);",
        &[],
    )
    .unwrap();

    let err = conn
        .execute("SELECT $1::session_id", &[&SessionId(vec![])])
        .unwrap_err();
    assert!(err.source().unwrap().is::<WrongType>());
}

#[test]
#[ignore] // GaussDB doesn't support DOMAIN
fn wrong_type() {
    #[derive(FromSql, ToSql, Debug, PartialEq)]
    #[gaussdb(name = "session_id")]
    struct SessionId(i32);

    let mut conn = Client::connect(
        &get_test_conn_str(),
        NoTls,
    )
    .unwrap();
    conn.execute(
        "CREATE DOMAIN pg_temp.session_id AS bytea CHECK(octet_length(VALUE) = 16);",
        &[],
    )
    .unwrap();

    let err = conn
        .execute("SELECT $1::session_id", &[&SessionId(0)])
        .unwrap_err();
    assert!(err.source().unwrap().is::<WrongType>());
}

#[test]
#[ignore] // GaussDB doesn't support DOMAIN
fn domain_in_composite() {
    #[derive(FromSql, ToSql, Debug, PartialEq)]
    #[gaussdb(name = "domain")]
    struct Domain(String);

    #[derive(FromSql, ToSql, Debug, PartialEq)]
    #[gaussdb(name = "composite")]
    struct Composite {
        domain: Domain,
    }

    let mut conn = Client::connect(
        &get_test_conn_str(),
        NoTls,
    )
    .unwrap();
    conn.batch_execute(
        "
            CREATE DOMAIN pg_temp.domain AS TEXT;\
            CREATE TYPE pg_temp.composite AS (
                domain domain
            );
        ",
    )
    .unwrap();

    test_type(
        &mut conn,
        "composite",
        &[(
            Composite {
                domain: Domain("hello".to_string()),
            },
            "ROW('hello')",
        )],
    );
}
