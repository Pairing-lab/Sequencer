use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use revm::{db::EmptyDB, Evm, inspectors::NoOpInspector, inspector_handle_register};
use serde::{Deserialize, Serialize};


fn handle_client(mut stream: TcpStream, evm: &mut Evm<'_, NoOpInspector, EmptyDB>) -> () {
  
            let tx = evm.tx_mut();

            (*tx).gas_limit -= 100;
                

            let output = evm.transact();


            let x = &evm.context.evm.env.tx;

            println!("Transaction executed: {:?}", x);

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
            Ok(stream) => {
                    handle_client(stream, &mut evm);
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
    Ok(())
}
