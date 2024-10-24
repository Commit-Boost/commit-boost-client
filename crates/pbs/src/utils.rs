use cb_common::pbs::error::PbsError;
use futures::StreamExt;
use reqwest::Response;

pub async fn read_chunked_body_with_max(
    res: Response,
    max_size: usize,
) -> Result<Vec<u8>, PbsError> {
    let mut stream = res.bytes_stream();
    let mut response_bytes = Vec::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if response_bytes.len() + chunk.len() > max_size {
            // avoid spamming logs if the message is too large
            response_bytes.truncate(1024);
            return Err(PbsError::PayloadTooLarge {
                max: max_size,
                raw: String::from_utf8_lossy(&response_bytes).into_owned(),
            });
        }

        response_bytes.extend_from_slice(&chunk);
    }

    Ok(response_bytes)
}
