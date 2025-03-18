use nom::{bytes::complete, error::Error, number, IResult};

pub fn string_upto_null_terminator(bytes: &[u8]) -> IResult<&[u8], String> {
    let (bytes, name_bytes) = match complete::take_until::<&str, &[u8], Error<&[u8]>>("\0")(bytes) {
        Ok((bytes, name_bytes)) => (bytes, name_bytes),
        Err(_) => return Ok((&[], String::from_utf8(bytes.to_vec()).unwrap())),
    };
    let name = String::from_utf8(name_bytes.to_vec()).unwrap();
    Ok((&bytes[1..], name))
}

pub fn version_string(version: u32) -> String {
    format!(
        "{}.{}.{}",
        (version >> 16) & 0xff,
        (version >> 8) & 0xff,
        version & 0xff
    )
}

pub fn reverse_version_string(versiong: String) -> u32 {
    let parts: Vec<&str> = versiong.split('.').collect();
    let major = parts[0].parse::<u32>().unwrap();
    let minor = parts[1].parse::<u32>().unwrap();
    let revision = parts[2].parse::<u32>().unwrap();
    (major << 16) | (minor << 8) | revision
}

pub fn read_uleb(bytes: &[u8]) -> IResult<&[u8], u64> {
    let mut result = 0;
    let mut shift = 0;
    let mut cursor = bytes;

    loop {
        let (remaining, byte) = number::complete::u8(cursor)?;
        cursor = remaining;

        result |= ((byte & 0x7f) as u64) << shift;
        if (byte & 0x80) == 0 {
            break;
        }
        shift += 7;
    }

    Ok((cursor, result))
}

pub fn read_uleb_many<'a>(mut bytes: &'a [u8]) -> IResult<&'a [u8], Vec<u64>> {
    let mut result = Vec::new();
    if bytes.is_empty() {
        return Ok((bytes, result));
    }

    loop {
        let (remaining, value) = read_uleb(bytes)?;
        bytes = remaining;
        result.push(value);

        if bytes.is_empty() {
            break;
        }
    }

    Ok((bytes, result))
}

pub fn read_sleb(bytes: &[u8]) -> IResult<&[u8], i64> {
    let mut result = 0;
    let mut shift = 0;
    let mut cursor = bytes;
    let mut byte;

    loop {
        let (remaining, current) = number::complete::u8(cursor)?;
        cursor = remaining;
        byte = current;

        result |= ((byte & 0x7f) as i64) << shift;
        shift += 7;

        if (byte & 0x80) == 0 {
            break;
        }
    }

    if shift < 8 * std::mem::size_of::<i64>() && (byte & 0x40) != 0 {
        result |= -(1 << shift);
    }

    Ok((cursor, result))
}
