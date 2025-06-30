use actix_web::{post, web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_instruction,
};
use spl_token::instruction as token_instruction;
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{
    Keypair as DalekKeypair, PublicKey as DalekPubkey, SecretKey as DalekSecretKey, Signature,
    Signer as DalekSigner, Verifier,
};
use bs58;
use std::env;

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

#[post("/keypair")]
async fn generate_keypair() -> impl Responder {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();

    HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(KeypairResponse { pubkey, secret }),
        error: None,
    })
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    mintAuthority: String,
    mint: String,
    decimals: u8,
}

#[derive(Serialize)]
struct AccountMetaResponse {
    pub pubkey: String,
    pub is_signer: bool,
    pub is_writable: bool,
}

#[derive(Serialize)]
struct InstructionResponse {
    program_id: String,
    accounts: Vec<AccountMetaResponse>,
    instruction_data: String,
}

#[post("/token/create")]
async fn create_token(req: web::Json<CreateTokenRequest>) -> impl Responder {
    let mint_pubkey = match req.mint.parse::<Pubkey>() {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid mint pubkey".to_string()),
            })
        }
    };

    let mint_authority_pubkey = match req.mintAuthority.parse::<Pubkey>() {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid mintAuthority pubkey".to_string()),
            })
        }
    };

    let ix = match token_instruction::initialize_mint(
        &spl_token::id(),
        &mint_pubkey,
        &mint_authority_pubkey,
        None,
        req.decimals,
    ) {
        Ok(i) => i,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Failed to build initialize_mint instruction".to_string()),
            })
        }
    };

    let accounts = ix
        .accounts
        .iter()
        .map(|a| AccountMetaResponse {
            pubkey: a.pubkey.to_string(),
            is_signer: a.is_signer,
            is_writable: a.is_writable,
        })
        .collect();

    let instruction_data = general_purpose::STANDARD.encode(ix.data);

    HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(InstructionResponse {
            program_id: ix.program_id.to_string(),
            accounts,
            instruction_data,
        }),
        error: None,
    })
}

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[post("/token/mint")]
async fn mint_token(req: web::Json<MintTokenRequest>) -> impl Responder {
    let mint = match req.mint.parse::<Pubkey>() {
        Ok(p) => p,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid mint pubkey".to_string()),
            })
        }
    };

    let destination = match req.destination.parse::<Pubkey>() {
        Ok(p) => p,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid destination pubkey".to_string()),
            })
        }
    };

    let authority = match req.authority.parse::<Pubkey>() {
        Ok(p) => p,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid authority pubkey".to_string()),
            })
        }
    };

    let ix = match token_instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        req.amount,
    ) {
        Ok(i) => i,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Failed to build mint_to instruction".to_string()),
            })
        }
    };

    let accounts = ix
        .accounts
        .iter()
        .map(|a| AccountMetaResponse {
            pubkey: a.pubkey.to_string(),
            is_signer: a.is_signer,
            is_writable: a.is_writable,
        })
        .collect();

    let instruction_data = general_purpose::STANDARD.encode(ix.data);

    HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(InstructionResponse {
            program_id: ix.program_id.to_string(),
            accounts,
            instruction_data,
        }),
        error: None,
    })
}

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    signature: String,
    public_key: String,
    message: String,
}

#[post("/message/sign")]
async fn sign_message(req: web::Json<SignMessageRequest>) -> impl Responder {
    let secret_bytes = match bs58::decode(&req.secret).into_vec() {
        Ok(b) => b,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid secret key (not base58)".to_string()),
            })
        }
    };

    let keypair = match DalekKeypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Failed to parse secret key".to_string()),
            })
        }
    };

    let signature = keypair.sign(req.message.as_bytes());

    HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(SignMessageResponse {
            signature: general_purpose::STANDARD.encode(signature.to_bytes()),
            public_key: bs58::encode(keypair.public.to_bytes()).into_string(),
            message: req.message.clone(),
        }),
        error: None,
    })
}

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

#[post("/message/verify")]
async fn verify_message(req: web::Json<VerifyMessageRequest>) -> impl Responder {
    let sig_bytes = match general_purpose::STANDARD.decode(&req.signature) {
        Ok(b) => b,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid signature encoding (expected base64)".to_string()),
            })
        }
    };

    let pubkey_bytes = match bs58::decode(&req.pubkey).into_vec() {
        Ok(b) => b,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid public key (not base58)".to_string()),
            })
        }
    };

    let pubkey = match DalekPubkey::from_bytes(&pubkey_bytes) {
        Ok(p) => p,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid pubkey length".to_string()),
            })
        }
    };

    let signature = match Signature::from_bytes(&sig_bytes) {
        Ok(sig) => sig,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid signature format".to_string()),
            })
        }
    };

    let is_valid = pubkey.verify(req.message.as_bytes(), &signature).is_ok();

    HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(VerifyMessageResponse {
            valid: is_valid,
            message: req.message.clone(),
            pubkey: req.pubkey.clone(),
        }),
        error: None,
    })
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[post("/send/sol")]
async fn send_sol(req: web::Json<SendSolRequest>) -> impl Responder {
    let from = match req.from.parse::<Pubkey>() {
        Ok(p) => p,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid from pubkey".to_string()),
            })
        }
    };

    let to = match req.to.parse::<Pubkey>() {
        Ok(p) => p,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid to pubkey".to_string()),
            })
        }
    };

    let ix = system_instruction::transfer(&from, &to, req.lamports);

    let accounts: Vec<String> = ix.accounts.iter().map(|a| a.pubkey.to_string()).collect();
    let instruction_data = general_purpose::STANDARD.encode(ix.data);

    HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(serde_json::json!({
            "program_id": ix.program_id.to_string(),
            "accounts": accounts,
            "instruction_data": instruction_data
        })),
        error: None,
    })
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[post("/send/token")]
async fn send_token(req: web::Json<SendTokenRequest>) -> impl Responder {
    let mint = match req.mint.parse::<Pubkey>() {
        Ok(p) => p,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid mint pubkey".to_string()),
            })
        }
    };

    let destination = match req.destination.parse::<Pubkey>() {
        Ok(p) => p,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid destination pubkey".to_string()),
            })
        }
    };

    let owner = match req.owner.parse::<Pubkey>() {
        Ok(p) => p,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Invalid owner pubkey".to_string()),
            })
        }
    };

    let ix = match token_instruction::transfer(&spl_token::id(), &mint, &destination, &owner, &[], req.amount) {
        Ok(i) => i,
        Err(_) => {
            return HttpResponse::Ok().json(ApiResponse::<()> {
                success: false,
                data: None,
                error: Some("Failed to build transfer instruction".to_string()),
            })
        }
    };

    let accounts: Vec<_> = ix.accounts.iter().map(|a| serde_json::json!({
        "pubkey": a.pubkey.to_string(),
        "isSigner": a.is_signer
    })).collect();

    let instruction_data = general_purpose::STANDARD.encode(ix.data);

    HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(serde_json::json!({
            "program_id": ix.program_id.to_string(),
            "accounts": accounts,
            "instruction_data": instruction_data
        })),
        error: None,
    })
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr = format!("0.0.0.0:{}", port);
    println!("Running server on {}", addr);

    HttpServer::new(|| {
        App::new()
            .service(generate_keypair)
            .service(create_token)
            .service(mint_token)
            .service(sign_message)
            .service(verify_message)
            .service(send_sol)
            .service(send_token)
    })
    .bind(addr)?
    .run()
    .await
}
