import busboy from 'busboy';
import type { Request } from 'express';
import { HttpError } from './context.ts';

export interface ParsedUpload {
  fields: Record<string, string>;
  file: { filename: string; data: Buffer } | null;
}

/**
 * Parse a multipart upload with hard limits: one file, at most maxBytes (we
 * read one byte past the limit to detect oversize and refuse it, never
 * truncate silently), 10 small text fields. The whole file is held in memory
 * because it must be encrypted before it touches disk; maxBytes bounds that.
 */
export function parseUpload(req: Request, maxBytes: number): Promise<ParsedUpload> {
  return new Promise((resolve, reject) => {
    const ct = req.headers['content-type'] ?? '';
    if (!ct.toLowerCase().startsWith('multipart/form-data')) {
      return reject(new HttpError(415, 'unsupported_media_type', 'Expected multipart/form-data'));
    }
    let bb: busboy.Busboy;
    try {
      bb = busboy({
        headers: req.headers,
        limits: { files: 1, fileSize: maxBytes + 1, fields: 10, fieldSize: 4096, parts: 12, fieldNameSize: 50 },
        defParamCharset: 'utf8',
      });
    } catch {
      return reject(new HttpError(400, 'bad_multipart', 'Malformed multipart request'));
    }
    const fields: Record<string, string> = {};
    let file: ParsedUpload['file'] = null;
    let failed: HttpError | null = null;
    const fail = (e: HttpError) => {
      if (!failed) failed = e;
    };

    bb.on('field', (name, value, info) => {
      if (info.valueTruncated) fail(new HttpError(400, 'field_too_long', `Field ${name} is too long`));
      if (name in fields) fail(new HttpError(400, 'duplicate_field', `Field ${name} was sent twice`));
      fields[name] = value;
    });
    bb.on('file', (name, stream, info) => {
      if (name !== 'file' || file) {
        fail(new HttpError(400, 'unexpected_file', 'Exactly one file, in field "file", is expected'));
        stream.resume();
        return;
      }
      const chunks: Buffer[] = [];
      let size = 0;
      stream.on('data', (c: Buffer) => {
        size += c.length;
        if (size <= maxBytes) chunks.push(c);
      });
      stream.on('limit', () => fail(new HttpError(413, 'file_too_large', `File exceeds ${maxBytes} bytes`)));
      stream.on('close', () => {
        if (size <= maxBytes) file = { filename: info.filename ?? '', data: Buffer.concat(chunks) };
      });
    });
    bb.on('filesLimit', () => fail(new HttpError(400, 'too_many_files', 'Only one file per upload')));
    bb.on('fieldsLimit', () => fail(new HttpError(400, 'too_many_fields', 'Too many form fields')));
    bb.on('partsLimit', () => fail(new HttpError(400, 'too_many_parts', 'Too many form parts')));
    bb.on('error', () => fail(new HttpError(400, 'bad_multipart', 'Malformed multipart request')));
    bb.on('close', () => (failed ? reject(failed) : resolve({ fields, file })));
    req.pipe(bb);
  });
}
