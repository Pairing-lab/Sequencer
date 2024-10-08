use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use revm::{db::EmptyDB, Evm, inspectors::NoOpInspector, inspector_handle_register};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Deserialize, Debug)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: Vec<Value>,
    id: u64,
}

#[derive(Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    result: Value,
    id: u64,
}

fn handle_rpc_request(request: JsonRpcRequest, evm: &mut Evm<'_, NoOpInspector, EmptyDB>) -> JsonRpcResponse {
    println!("Received RPC request: {:?}", request);  // Log the received request

    match request.method.as_str() {
        "eth_call" => {
            JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: json!({
                    "status": "0x1",
                    "gasUsed": "0x5208",
                    "returnValue": "0x"
                }),
                id: request.id,
            }
        },
        "eth_getBalance" => {
            JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: json!("0x0"),
                id: request.id,
            }
        },
        _ => {
            JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: json!({
                    "error": {
                        "code": -32601,
                        "message": "Method not found"
                    }
                }),
                id: request.id,
            }
        }
    }
}

fn handle_client(mut stream: TcpStream, evm: &mut Evm<'_, NoOpInspector, EmptyDB>) {
    let mut buffer = [0; 1024];
    match stream.read(&mut buffer) {
        Ok(size) => {
            let received = String::from_utf8_lossy(&buffer[..size]);
            println!("Received data: {}", received);  // Log the raw received data

            match serde_json::from_str::<JsonRpcRequest>(&received) {
                Ok(request) => {
                    let response = handle_rpc_request(request, evm);
                    let response_json = serde_json::to_string(&response).unwrap();
                    stream.write_all(response_json.as_bytes()).unwrap();
                },
                Err(e) => {
                    println!("Failed to parse JSON-RPC request: {}", e);
                    let error_response = json!({
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32700,
                            "message": "Parse error"
                        },
                        "id": null
                    });
                    stream.write_all(error_response.to_string().as_bytes()).unwrap();
                }
            }
        },
        Err(e) => println!("Error reading from stream: {}", e),
    }

    let tx = evm.tx_mut();
    (*tx).gas_limit -= 100;
    let output = evm.transact();
    println!("Transaction executed: {:?}", evm.context.evm.env.tx);
}

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:8080")?;
    println!("Server listening on port 8080");

    let mut evm = Evm::builder()
    .with_db(EmptyDB::default())
    .with_external_context(NoOpInspector)
    .append_handler_register(inspector_handle_register)
    .build();

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let mut buffer = [0; 1024];
                match stream.read(&mut buffer) {
                    Ok(size) => {
                        let received = String::from_utf8_lossy(&buffer[..size]);
                        println!("Received data: {}", received);  // Log the raw received data

                        match serde_json::from_str::<JsonRpcRequest>(&received) {
                            Ok(request) => {
                                let response = handle_rpc_request(request, &mut evm);
                                let response_json = serde_json::to_string(&response).unwrap();
                                stream.write_all(response_json.as_bytes()).unwrap();
                            },
                            Err(e) => {
                                println!("Failed to parse JSON-RPC request: {}", e);
                                let error_response = json!({
                                    "jsonrpc": "2.0",
                                    "error": {
                                        "code": -32700,
                                        "message": "Parse error"
                                    },
                                    "id": null
                                });
                                stream.write_all(error_response.to_string().as_bytes()).unwrap();
                            }
                        }
                    },
                    Err(e) => println!("Error reading from stream: {}", e),
                }

                // Example of modifying EVM state
                let tx = evm.tx_mut();
                (*tx).gas_limit -= 100;
                let _output = evm.transact();
                println!("Transaction executed: {:?}", evm.context.evm.env.tx);
            },
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
    Ok(())
}
