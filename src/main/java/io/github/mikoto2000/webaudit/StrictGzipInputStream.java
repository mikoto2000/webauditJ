package io.github.mikoto2000.webaudit;

import java.io.*;
import java.util.zip.*;

/** RFC 1952 members, CRCs, lengths and trailing bytes are all checked. */
final class StrictGzipInputStream extends InputStream {
  private final PushbackInputStream input;
  private final Inflater inflater = new Inflater(true);
  private final CRC32 crc = new CRC32();
  private final byte[] compressed = new byte[65536];
  private int supplied;
  private long memberBytes;
  private boolean end, closed;

  StrictGzipInputStream(InputStream input) throws IOException {
    this.input = new PushbackInputStream(input, compressed.length);
    try {
      header(false);
    } catch (IOException ex) {
      inflater.end();
      throw ex;
    }
  }

  private int required() throws IOException {
    int c = input.read();
    if (c < 0) throw new EOFException("unexpected EOF in gzip");
    return c;
  }

  private boolean header(boolean allowEnd) throws IOException {
    int first = input.read();
    if (first < 0 && allowEnd) {
      end = true;
      return false;
    }
    if (first < 0) throw new EOFException("unexpected EOF in gzip header");
    CRC32 headerCrc = new CRC32();
    headerCrc.update(first);
    int second = headerByte(headerCrc),
        method = headerByte(headerCrc),
        flags = headerByte(headerCrc);
    if (first != 0x1f || second != 0x8b || method != 8 || (flags & 0xe0) != 0)
      throw new IOException("invalid gzip header");
    for (int i = 0; i < 6; i++) headerByte(headerCrc);
    if ((flags & 4) != 0) {
      int length = headerByte(headerCrc) | (headerByte(headerCrc) << 8);
      for (int i = 0; i < length; i++) headerByte(headerCrc);
    }
    if ((flags & 8) != 0) headerString(headerCrc);
    if ((flags & 16) != 0) headerString(headerCrc);
    if ((flags & 2) != 0) {
      int expected = required() | (required() << 8);
      if (expected != (headerCrc.getValue() & 0xffff))
        throw new IOException("invalid gzip header checksum");
    }
    crc.reset();
    memberBytes = 0;
    inflater.reset();
    supplied = 0;
    return true;
  }

  private int headerByte(CRC32 checksum) throws IOException {
    int c = required();
    checksum.update(c);
    return c;
  }

  private void headerString(CRC32 checksum) throws IOException {
    for (int i = 0; i < 512; i++) if (headerByte(checksum) == 0) return;
    throw new IOException("gzip header name/comment exceeds limit");
  }

  private long uint32() throws IOException {
    return (long) required()
        | ((long) required() << 8)
        | ((long) required() << 16)
        | ((long) required() << 24);
  }

  private void trailer() throws IOException {
    int remaining = inflater.getRemaining();
    if (remaining > 0) input.unread(compressed, supplied - remaining, remaining);
    long expectedCrc = uint32(), expectedSize = uint32();
    if (expectedCrc != crc.getValue() || expectedSize != (memberBytes & 0xffffffffL))
      throw new IOException("gzip checksum error");
    header(true);
  }

  public int read(byte[] bytes, int offset, int length) throws IOException {
    java.util.Objects.checkFromIndexSize(offset, length, bytes.length);
    if (closed) throw new IOException("gzip stream closed");
    if (length == 0) return 0;
    while (!end) {
      try {
        int n = inflater.inflate(bytes, offset, length);
        if (n > 0) {
          crc.update(bytes, offset, n);
          memberBytes += n;
          return n;
        }
      } catch (DataFormatException ex) {
        throw new IOException("invalid gzip deflate data", ex);
      }
      if (inflater.finished()) {
        trailer();
        continue;
      }
      if (inflater.needsDictionary()) throw new IOException("gzip dictionary is unsupported");
      if (inflater.needsInput()) {
        supplied = input.read(compressed);
        if (supplied < 0) throw new EOFException("unexpected EOF in gzip data");
        inflater.setInput(compressed, 0, supplied);
      } else throw new IOException("invalid gzip state");
    }
    return -1;
  }

  public int read() throws IOException {
    byte[] b = new byte[1];
    return read(b, 0, 1) < 0 ? -1 : b[0] & 255;
  }

  public void close() throws IOException {
    if (!closed) {
      closed = true;
      inflater.end();
      input.close();
    }
  }
}
