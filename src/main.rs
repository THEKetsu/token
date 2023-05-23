
use actix_web::{web, App, Error, HttpResponse, HttpServer,Responder, HttpRequest,get, http::uri::Authority, };
use serde::{Deserialize, Serialize};
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, DecodingKey};

/// Our claims struct, it needs to derive `Serialize` and/or `Deserialize`
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    admin: String,
    login: String,
    exp: usize,
}

#[get("/check_token")]
 pub async fn check_token(req:HttpRequest ) -> impl Responder {
    println!("check token");
    let header = req.headers().get("Authorization").unwrap();
    let token_to_decode = header.to_str().unwrap();
    // decode token
    let decoded_token = decode::<Claims>(&token_to_decode, &DecodingKey::from_secret("bifrost".as_ref()), &Validation::default())
    .unwrap();

    let token: Claims = decoded_token.claims;

    println!("{:?}",token);


    if "true" == "true" {
        // retunr a HEADER Authorization with authorization
        return HttpResponse::Ok()
        .insert_header(("Authorization","True"))
        .content_type("application/json")
        .body("You are an admin")
        ;
    } 
    else {
        return HttpResponse::Ok().body("You are not an admin");
    }

 }
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(check_token)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}