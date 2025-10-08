use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use flate2::write::ZlibEncoder;
use flate2::read::ZlibDecoder;
use flate2::Compression;
use serde_json::{Value, to_string_pretty, from_str};
use std::io::{Write, Read};

const PREFIX: &str = "vpn://";

/// Преобразует JSON конфигурацию в VPN URL
pub fn encode(config: &Value) -> Result<String, Box<dyn std::error::Error>> {
    // 1. Сериализация в JSON с отступами
    let json_string = to_string_pretty(config)?;
    let original_data = json_string.as_bytes();
    let original_data_len = original_data.len() as u32;
    
    // 2. Сжатие данных
    let compressed_data = compress_data(original_data)?;
    
    // 3. Создание заголовка (4 байта, Big Endian)
    let header = create_header(original_data_len);
    
    // 4. Объединение заголовка и сжатых данных
    let mut combined = header.to_vec();
    combined.extend_from_slice(&compressed_data);
    
    // 5. Base64 URL-safe кодирование (без padding)
    let encoded = encode_base64(&combined);
    
    // 6. Добавление префикса
    Ok(format!("{}{}", PREFIX, encoded))
}

/// Декодирует VPN URL обратно в JSON конфигурацию
pub fn decode(vpn_url: &str) -> Result<Value, Box<dyn std::error::Error>> {
    // Удаление префикса
    let encoded_data = vpn_url.strip_prefix(PREFIX)
        .ok_or("Invalid VPN URL: missing prefix")?;
    
    // Декодирование Base64
    let decoded = decode_base64(encoded_data)?;
    
    // Попытка декодирования с заголовком и сжатием
    match try_decode_compressed(&decoded) {
        Ok(json) => Ok(json),
        Err(_) => {
            // Обратная совместимость: попытка декодирования как чистый Base64 JSON
            try_decode_plain(&decoded)
        }
    }
}

// === Helper функции ===

/// Сжимает данные используя zlib
fn compress_data(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

/// Распаковывает данные используя zlib
fn decompress_data(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

/// Создает 4-байтовый заголовок с длиной данных (Big Endian)
fn create_header(length: u32) -> [u8; 4] {
    length.to_be_bytes()
}

/// Считывает длину из 4-байтового заголовка (Big Endian)
fn read_header(header: &[u8]) -> u32 {
    u32::from_be_bytes([header[0], header[1], header[2], header[3]])
}

/// Кодирует данные в Base64 URL-safe без padding
fn encode_base64(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Декодирует Base64 URL-safe (автоматически обрабатывает отсутствие padding)
fn decode_base64(data: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(URL_SAFE_NO_PAD.decode(data)?)
}

/// Пытается декодировать данные с заголовком и сжатием
fn try_decode_compressed(data: &[u8]) -> Result<Value, Box<dyn std::error::Error>> {
    if data.len() < 4 {
        return Err("Data too short for header".into());
    }
    
    // Считываем ожидаемую длину из заголовка
    let expected_len = read_header(&data[..4]) as usize;
    
    // Распаковываем оставшиеся данные
    let decompressed = decompress_data(&data[4..])?;
    
    // Проверка целостности
    if decompressed.len() != expected_len {
        return Err(format!(
            "Data integrity check failed: expected {} bytes, got {}",
            expected_len,
            decompressed.len()
        ).into());
    }
    
    // Десериализация JSON
    let json_string = String::from_utf8(decompressed)?;
    Ok(from_str(&json_string)?)
}

/// Пытается декодировать данные как чистый Base64 JSON (без сжатия)
fn try_decode_plain(data: &[u8]) -> Result<Value, Box<dyn std::error::Error>> {
    let json_string = String::from_utf8(data.to_vec())?;
    Ok(from_str(&json_string)?)
}

/// Автоматически определяет тип входных данных
fn detect_input_type(input: &str) -> InputType {
    let trimmed = input.trim();
    
    // Проверка на VPN URL
    if trimmed.starts_with(PREFIX) {
        return InputType::VpnUrl;
    }
    
    // Проверка на JSON
    if (trimmed.starts_with('{') && trimmed.ends_with('}')) 
        || (trimmed.starts_with('[') && trimmed.ends_with(']')) {
        return InputType::Json;
    }
    
    // Попытка распарсить как JSON
    if from_str::<Value>(trimmed).is_ok() {
        return InputType::Json;
    }
    
    InputType::Unknown
}

#[derive(Debug, PartialEq)]
enum InputType {
    VpnUrl,
    Json,
    Unknown,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let mut explicit_mode: Option<String> = None;
    let mut input_file: Option<String> = None;
    let mut output_file: Option<String> = None;
    let mut direct_input: Vec<String> = Vec::new();
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-e" | "--encode" => explicit_mode = Some("encode".to_string()),
            "-d" | "--decode" => explicit_mode = Some("decode".to_string()),
            "-i" | "--input" => {
                if i + 1 < args.len() {
                    input_file = Some(args[i + 1].clone());
                    i += 1;
                } else {
                    eprintln!("Ошибка: не указан файл для -i");
                    std::process::exit(1);
                }
            }
            "-o" | "--output" => {
                if i + 1 < args.len() {
                    output_file = Some(args[i + 1].clone());
                    i += 1;
                } else {
                    eprintln!("Ошибка: не указан файл для -o");
                    std::process::exit(1);
                }
            }
            "-h" | "--help" => {
                print_usage(&args[0]);
                std::process::exit(0);
            }
            _ => direct_input.push(args[i].clone()),
        }
        i += 1;
    }

    // Получаем входные данные
    let input = get_input(input_file, direct_input)?;
    
    // Определяем режим работы
    let mode = if let Some(explicit) = explicit_mode {
        explicit
    } else {
        // Автодетект
        match detect_input_type(&input) {
            InputType::VpnUrl => {
                eprintln!("🔍 Автодетект: обнаружен VPN URL, выполняется декодирование");
                "decode".to_string()
            }
            InputType::Json => {
                eprintln!("🔍 Автодетект: обнаружен JSON, выполняется кодирование");
                "encode".to_string()
            }
            InputType::Unknown => {
                eprintln!("❌ Ошибка: не удалось определить тип входных данных");
                eprintln!("   Используйте -e для кодирования или -d для декодирования");
                std::process::exit(1);
            }
        }
    };

    // Выполняем операцию
    match mode.as_str() {
        "encode" => {
            let config: Value = from_str(&input)?;
            let encoded = encode(&config)?;
            write_output(output_file, &encoded)?;
        }
        "decode" => {
            let vpn_url = input.trim().to_string();
            let decoded = decode(&vpn_url)?;
            let output = to_string_pretty(&decoded)?;
            write_output(output_file, &output)?;
        }
        _ => unreachable!(),
    }

    Ok(())
}

fn get_input(file: Option<String>, direct: Vec<String>) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(filename) = file {
        read_file(&filename)
    } else if !direct.is_empty() {
        Ok(direct.join(" "))
    } else {
        read_stdin()
    }
}

fn write_output(file: Option<String>, content: &str) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(filename) = file {
        write_file(&filename, content)
    } else {
        println!("{}", content);
        Ok(())
    }
}

fn read_file(filename: &str) -> Result<String, Box<dyn std::error::Error>> {
    use std::fs;
    Ok(fs::read_to_string(filename)?)
}

fn write_file(filename: &str, content: &str) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;
    fs::write(filename, content)?;
    Ok(())
}

fn print_usage(program: &str) {
    eprintln!("VPN Config Encoder/Decoder");
    eprintln!();
    eprintln!("Использование:");
    eprintln!("  {} [-e|-d] [-i <input>] [-o <output>] [<data>]", program);
    eprintln!();
    eprintln!("Опции:");
    eprintln!("  -e, --encode       Явно указать режим кодирования");
    eprintln!("  -d, --decode       Явно указать режим декодирования");
    eprintln!("  -i, --input FILE   Читать из файла");
    eprintln!("  -o, --output FILE  Записать в файл");
    eprintln!("  -h, --help         Показать справку");
    eprintln!();
    eprintln!("Автодетект:");
    eprintln!("  Если не указаны -e/-d, программа автоматически определит");
    eprintln!("  тип данных (JSON или VPN URL) и выполнит нужную операцию.");
    eprintln!();
    eprintln!("Примеры:");
    eprintln!("  # Автодетект с файлами");
    eprintln!("  {} -i config.json -o vpn_url.txt", program);
    eprintln!("  {} -i vpn_url.txt -o config.json", program);
    eprintln!();
    eprintln!("  # Автодетект с прямым вводом");
    eprintln!("  {} '{{\"server\":\"example.com\"}}'", program);
    eprintln!("  {} 'vpn://AAAAHXic...'", program);
    eprintln!();
    eprintln!("  # Явное указание режима");
    eprintln!("  {} -e -i config.json", program);
    eprintln!("  {} -d -i vpn_url.txt", program);
    eprintln!();
    eprintln!("  # Работа с stdin/stdout");
    eprintln!("  cat config.json | {}", program);
    eprintln!("  echo 'vpn://...' | {} -o decoded.json", program);
}

fn read_stdin() -> Result<String, Box<dyn std::error::Error>> {
    use std::io::{self, Read};
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_encode_decode() {
        let config = json!({
            "server": "example.com",
            "port": 8080,
            "protocol": "wireguard",
            "key": "test_key_12345"
        });

        let encoded = encode(&config).unwrap();
        assert!(encoded.starts_with(PREFIX));

        let decoded = decode(&encoded).unwrap();
        assert_eq!(config, decoded);
    }

    #[test]
    fn test_detect_input_type() {
        // JSON детект
        assert_eq!(detect_input_type(r#"{"key": "value"}"#), InputType::Json);
        assert_eq!(detect_input_type(r#"{"server":"test.com"}"#), InputType::Json);
        assert_eq!(detect_input_type(r#"[1, 2, 3]"#), InputType::Json);
        
        // VPN URL детект
        assert_eq!(detect_input_type("vpn://AAAAHXic"), InputType::VpnUrl);
        assert_eq!(detect_input_type("vpn://test123"), InputType::VpnUrl);
        
        // Unknown
        assert_eq!(detect_input_type("random text"), InputType::Unknown);
        assert_eq!(detect_input_type(""), InputType::Unknown);
    }

    #[test]
    fn test_helper_functions() {
        let data = b"Hello, World!";
        
        // Тест сжатия/распаковки
        let compressed = compress_data(data).unwrap();
        let decompressed = decompress_data(&compressed).unwrap();
        assert_eq!(data, decompressed.as_slice());
        
        // Тест заголовка
        let len = 12345u32;
        let header = create_header(len);
        let read_len = read_header(&header);
        assert_eq!(len, read_len);
        
        // Тест Base64
        let encoded = encode_base64(data);
        let decoded = decode_base64(&encoded).unwrap();
        assert_eq!(data, decoded.as_slice());
    }
}