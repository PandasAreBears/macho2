pub fn string_upto_null_terminator(bytes: &[u8]) -> nom::IResult<&[u8], String> {
    let (bytes, name_bytes) = match nom::bytes::complete::take_until::<
        &str,
        &[u8],
        nom::error::Error<&[u8]>,
    >("\0")(bytes)
    {
        Ok((bytes, name_bytes)) => (bytes, name_bytes),
        Err(_) => return Ok((&[], String::from_utf8(bytes.to_vec()).unwrap())),
    };
    let name = String::from_utf8(name_bytes.to_vec()).unwrap();
    Ok((&bytes[1..], name))
}

pub fn string_upto_null_terminator_many(bytes: &[u8]) -> nom::IResult<&[u8], Vec<String>> {
    let mut strings = Vec::new();
    let mut remaining_bytes = bytes;
    loop {
        let (bytes, name) = string_upto_null_terminator(remaining_bytes)?;
        strings.push(name);
        if bytes.is_empty() {
            break;
        }
        remaining_bytes = bytes;
    }
    Ok((&[], strings))
}

pub fn version_string(version: u32) -> String {
    format!(
        "{}.{}.{}",
        (version >> 16) & 0xff,
        (version >> 8) & 0xff,
        version & 0xff
    )
}
