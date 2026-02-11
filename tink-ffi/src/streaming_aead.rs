// Copyright 2026 Adam Winstanley
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::io;

use crate::error::{check_status, take_bytes, Result};
use crate::keyset::KeysetHandle;
use crate::sealed;

pub trait StreamingAead {
    fn new_encrypting_writer<W: io::Write>(
        &self,
        writer: W,
        aad: &[u8],
    ) -> Result<EncryptingWriter<W>>;

    fn new_decrypting_reader<R: io::Read>(
        &self,
        reader: R,
        aad: &[u8],
    ) -> Result<DecryptingReader<R>>;
}

// ---------------------------------------------------------------------------
// StreamingAeadPrimitive
// ---------------------------------------------------------------------------

pub struct StreamingAeadPrimitive {
    raw: *mut tink_ffi_sys::TinkStreamingAead,
}

unsafe impl Send for StreamingAeadPrimitive {}
unsafe impl Sync for StreamingAeadPrimitive {}

impl Drop for StreamingAeadPrimitive {
    fn drop(&mut self) {
        unsafe { tink_ffi_sys::tink_streaming_aead_free(self.raw) }
    }
}

impl sealed::Sealed for StreamingAeadPrimitive {}

impl crate::Primitive for StreamingAeadPrimitive {
    fn from_keyset_handle(handle: &KeysetHandle) -> Result<Self> {
        let mut raw = std::ptr::null_mut();
        check_status(unsafe { tink_ffi_sys::tink_streaming_aead_new(handle.as_raw(), &mut raw) })?;
        Ok(Self { raw })
    }
}

impl StreamingAead for StreamingAeadPrimitive {
    fn new_encrypting_writer<W: io::Write>(
        &self,
        writer: W,
        aad: &[u8],
    ) -> Result<EncryptingWriter<W>> {
        let mut stream = std::ptr::null_mut();
        check_status(unsafe {
            tink_ffi_sys::tink_streaming_aead_encrypt_start(
                self.raw,
                aad.as_ptr(),
                aad.len(),
                &mut stream,
            )
        })?;
        Ok(EncryptingWriter {
            stream,
            writer: Some(writer),
            finalized: false,
        })
    }

    fn new_decrypting_reader<R: io::Read>(
        &self,
        mut reader: R,
        aad: &[u8],
    ) -> Result<DecryptingReader<R>> {
        // Read all ciphertext into memory so we can pass it to the FFI.
        let mut ciphertext = Vec::new();
        reader
            .read_to_end(&mut ciphertext)
            .map_err(|e| crate::TinkError {
                message: format!("failed to read ciphertext: {e}"),
                code: -1,
            })?;

        let mut stream = std::ptr::null_mut();
        check_status(unsafe {
            tink_ffi_sys::tink_streaming_aead_decrypt_start(
                self.raw,
                ciphertext.as_ptr(),
                ciphertext.len(),
                aad.as_ptr(),
                aad.len(),
                &mut stream,
            )
        })?;

        Ok(DecryptingReader {
            stream,
            _reader: reader,
            _ciphertext: ciphertext,
        })
    }
}

// ---------------------------------------------------------------------------
// EncryptingWriter
// ---------------------------------------------------------------------------

pub struct EncryptingWriter<W> {
    stream: *mut tink_ffi_sys::TinkEncryptingStream,
    writer: Option<W>,
    finalized: bool,
}

unsafe impl<W: Send> Send for EncryptingWriter<W> {}

impl<W: io::Write> EncryptingWriter<W> {
    /// Finalize the encryption and flush all remaining ciphertext to the
    /// underlying writer. This must be called when done writing plaintext.
    pub fn finalize(mut self) -> Result<W> {
        self.do_finalize()?;
        self.writer.take().ok_or_else(|| crate::TinkError {
            message: "writer already consumed".into(),
            code: -1,
        })
    }

    fn do_finalize(&mut self) -> Result<()> {
        if self.finalized {
            return Ok(());
        }
        self.finalized = true;

        let mut ct_out = std::ptr::null_mut();
        let mut ct_len = 0;
        check_status(unsafe {
            tink_ffi_sys::tink_encrypting_stream_finalize(self.stream, &mut ct_out, &mut ct_len)
        })?;

        let ct = unsafe { take_bytes(ct_out, ct_len) };
        let writer = self.writer.as_mut().ok_or_else(|| crate::TinkError {
            message: "writer already consumed".into(),
            code: -1,
        })?;
        writer.write_all(&ct).map_err(|e| crate::TinkError {
            message: format!("failed to write ciphertext: {e}"),
            code: -1,
        })?;
        writer.flush().map_err(|e| crate::TinkError {
            message: format!("failed to flush writer: {e}"),
            code: -1,
        })?;
        Ok(())
    }
}

impl<W: io::Write> io::Write for EncryptingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.finalized || self.writer.is_none() {
            return Err(io::Error::other("stream already finalized"));
        }
        let mut written = 0;
        check_status(unsafe {
            tink_ffi_sys::tink_encrypting_stream_write(
                self.stream,
                buf.as_ptr(),
                buf.len(),
                &mut written,
            )
        })
        .map_err(|e| io::Error::other(e.message))?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<W> Drop for EncryptingWriter<W> {
    fn drop(&mut self) {
        if !self.finalized {
            // Best-effort: free the stream without finalizing.
            unsafe { tink_ffi_sys::tink_encrypting_stream_free(self.stream) }
        }
    }
}

// ---------------------------------------------------------------------------
// DecryptingReader
// ---------------------------------------------------------------------------

pub struct DecryptingReader<R> {
    stream: *mut tink_ffi_sys::TinkDecryptingStream,
    _reader: R,
    // Keep ciphertext alive for the lifetime of the decrypting stream.
    _ciphertext: Vec<u8>,
}

unsafe impl<R: Send> Send for DecryptingReader<R> {}

impl<R> io::Read for DecryptingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut read_out = 0;
        check_status(unsafe {
            tink_ffi_sys::tink_decrypting_stream_read(
                self.stream,
                buf.as_mut_ptr(),
                buf.len(),
                &mut read_out,
            )
        })
        .map_err(|e| io::Error::other(e.message))?;
        Ok(read_out)
    }
}

impl<R> Drop for DecryptingReader<R> {
    fn drop(&mut self) {
        unsafe { tink_ffi_sys::tink_decrypting_stream_free(self.stream) }
    }
}
