use crate::{TcpListener, TcpStream};
use std::io::{Read, Write};
use serde_json::{json, Value};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

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


pub fn rpc_handler(listener: Arc<TcpListener>) {
    for stream in listener.incoming(){
        match stream{
        Ok(mut stream) => {
            let mut buffer = [0; 1024];
            match stream.read(&mut buffer){
                Ok(size )=>{
                    let received = String::from_utf8_lossy(&buffer[..size]);
                    println!("Received data: {}", received);  // Log the raw received data

                    match serde_json::from_str::<JsonRpcRequest>(&received) {
                        Ok(request) => {
                            let response = handle_rpc_request(request);
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
                }
                Err(e) => {
                    println!("Error reading from stream: {}", e)
                }
            }
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }
    }
}


fn handle_rpc_request(request: JsonRpcRequest) -> JsonRpcResponse {
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