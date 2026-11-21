/**
 * Safe Document Content Extractor
 *
 * Safely extracts text and indicators from PDF, DOCX, CSV, TXT, and raw emails
 * without executing JavaScript, macros, external relationships, or formulas.
 */

import zlib from 'zlib';

export interface ExtractedDocumentContent {
  text: string;
  urls: string[];
  phones: string[];
  upiIds: string[];
  emails: string[];
  metadata: Record<string, any>;
}

export class SafeDocumentParser {
  /**
   * Safely extracts text and indicators from supported document buffers
   */
  static async parseDocument(
    buffer: Buffer,
    mimeType: string,
    filename: string
  ): Promise<ExtractedDocumentContent> {
    const ext = filename.split('.').pop()?.toLowerCase() || '';

    let rawText = '';
    const metadata: Record<string, any> = { filename, mimeType, sizeBytes: buffer.length };

    // 1. Plain Text / Markdown / Log
    if (mimeType.includes('text/plain') || ext === 'txt' || ext === 'log') {
      rawText = buffer.toString('utf-8');
    }
    // 2. CSV files (sanitize formula injection tokens =, +, -, @)
    else if (mimeType.includes('csv') || ext === 'csv') {
      const content = buffer.toString('utf-8');
      const sanitizedLines = content.split('\n').map((line) => {
        return line
          .split(',')
          .map((cell) => {
            const trimmed = cell.trim();
            // Disarm CSV formula injection
            if (/^[=+\-@]/.test(trimmed)) {
              metadata.formulaDisarmed = true;
              return `'${trimmed}`;
            }
            return trimmed;
          })
          .join(', ');
      });
      rawText = sanitizedLines.join('\n');
    }
    // 3. PDF Files (safe stream extraction without JS execution)
    else if (mimeType.includes('pdf') || ext === 'pdf') {
      const pdfString = buffer.toString('latin1');
      // Look for /JavaScript or /JS tags to flag malicious PDF structure
      if (pdfString.includes('/JavaScript') || pdfString.includes('/JS')) {
        metadata.suspiciousJsDetected = true;
      }
      // Extract text chunks between BT and ET operators
      const textMatches = pdfString.match(/\((.*?)\)\s*Tj/g) || [];
      const extractedChunks = textMatches.map((m) => m.replace(/^\(|\)\s*Tj$/g, ''));
      rawText = extractedChunks.join(' ');
      if (!rawText.trim()) {
        // Fallback: extract printable strings
        const asciiMatches = pdfString.match(/[a-zA-Z0-9\s.,:\/_\-@]{4,}/g) || [];
        rawText = asciiMatches.slice(0, 500).join(' ');
      }
    }
    // 4. DOCX Files (inspect XML stream safely)
    else if (
      mimeType.includes('vnd.openxmlformats-officedocument.wordprocessingml.document') ||
      ext === 'docx'
    ) {
      // Check for macros (VBA)
      const rawStr = buffer.toString('latin1');
      if (rawStr.includes('vbaProject.bin')) {
        metadata.vbaMacroDetected = true;
      }
      // Extract text inside <w:t> tags
      const textTags = rawStr.match(/<w:t[^>]*>(.*?)<\/w:t>/g) || [];
      const extractedWords = textTags.map((t) => t.replace(/<[^>]+>/g, ''));
      rawText = extractedWords.join(' ');
      if (!rawText.trim()) {
        const asciiMatches = rawStr.match(/[a-zA-Z0-9\s.,:\/_\-@]{4,}/g) || [];
        rawText = asciiMatches.slice(0, 500).join(' ');
      }
    }
    // 5. Raw Email (.eml / .msg text)
    else if (ext === 'eml' || mimeType.includes('message/rfc822')) {
      const emlStr = buffer.toString('utf-8');
      const subjectMatch = emlStr.match(/^Subject:\s*(.*)$/im);
      const fromMatch = emlStr.match(/^From:\s*(.*)$/im);
      const replyToMatch = emlStr.match(/^Reply-To:\s*(.*)$/im);

      metadata.subject = subjectMatch ? subjectMatch[1].trim() : '';
      metadata.from = fromMatch ? fromMatch[1].trim() : '';
      metadata.replyTo = replyToMatch ? replyToMatch[1].trim() : '';

      if (metadata.replyTo && metadata.from && metadata.replyTo !== metadata.from) {
        metadata.senderMismatch = true;
      }

      rawText = `Subject: ${metadata.subject}\nFrom: ${metadata.from}\n\n${emlStr}`;
    } else {
      // Default fallback
      rawText = buffer.toString('utf-8');
    }

    // Extract indicators from extracted text
    const urls = Array.from(
      new Set(rawText.match(/https?:\/\/[^\s<>\"'()]+/g) || [])
    );
    const phones = Array.from(
      new Set(rawText.match(/(?:\+91|0)?[-\s]?[6-9]\d{4}[-\s]?\d{5}/g) || [])
    );
    const upiIds = Array.from(
      new Set(
        rawText.match(/[\w\.\-]+@(okhdfcbank|okaxis|oksbi|okicici|paytm|ybl|apl|upi|axl|ibl)/gi) || []
      )
    );
    const emails = Array.from(
      new Set(rawText.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [])
    );

    return {
      text: rawText.slice(0, 15000), // Protect against memory DOS
      urls,
      phones,
      upiIds,
      emails,
      metadata,
    };
  }
}
