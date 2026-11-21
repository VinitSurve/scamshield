import { NextRequest, NextResponse } from 'next/server';
import { ScamShieldScanner, AnalysisResult } from '@/lib/analysis/scanner';
import { RedactionService } from '@/lib/auth/privacy';
import { RateLimiter } from '@/lib/auth/rate-limit';

export async function POST(req: NextRequest) {
  try {
    const ip = req.headers.get('x-forwarded-for') || '127.0.0.1';
    const rateCheck = RateLimiter.check(`analyze:${ip}`, 30, 60 * 1000);
    if (!rateCheck.allowed) {
      return NextResponse.json(
        { error: `Rate limit exceeded. Please wait ${Math.ceil(rateCheck.retryAfter / 1000)}s` },
        { status: 429 }
      );
    }

    const contentType = req.headers.get('content-type') || '';

    // Case 1: Multipart file upload (Images, PDFs, Docs)
    if (contentType.includes('multipart/form-data')) {
      const formData = await req.formData();
      const file = formData.get('file') as File | null;
      const textHint = (formData.get('text') as string) || '';

      if (!file && !textHint) {
        return NextResponse.json({ error: 'No file or text provided for analysis' }, { status: 400 });
      }

      if (file) {
        const allowedMime = [
          'image/png',
          'image/jpeg',
          'image/jpg',
          'image/webp',
          'application/pdf',
          'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
          'text/csv',
          'text/plain',
          'message/rfc822',
        ];

        if (!allowedMime.includes(file.type.toLowerCase())) {
          return NextResponse.json(
            { error: `Unsupported file type: ${file.type}. Allowed: PNG, JPEG, WEBP, PDF, DOCX, CSV, TXT, EML` },
            { status: 400 }
          );
        }

        const MAX_SIZE = 10 * 1024 * 1024; // 10MB
        if (file.size > MAX_SIZE) {
          return NextResponse.json({ error: 'File size exceeds limit of 10MB' }, { status: 400 });
        }

        // Sanitize filename against path traversal
        const safeFilename = file.name.replace(/[^a-zA-Z0-9._-]/g, '_');
        const arrayBuffer = await file.arrayBuffer();
        const buffer = Buffer.from(arrayBuffer);

        const result = await ScamShieldScanner.scanDocument(buffer, file.type, safeFilename);

        return NextResponse.json({
          success: true,
          mode: 'DOCUMENT_ANALYSIS',
          filename: safeFilename,
          result,
        });
      }
    }

    // Case 2: JSON Payload (Text, URL, Phone, UPI)
    const body = await req.json();
    const { text, url, phone, upi, type = 'TEXT', language = 'en' } = body;

    let result: AnalysisResult;

    if (type === 'URL' || (url && !text)) {
      result = await ScamShieldScanner.scanUrl(url || text);
    } else if (type === 'PHONE' || (phone && !text)) {
      const targetPhone = phone || text;
      result = await ScamShieldScanner.scanText(
        `Suspect caller phone number: ${targetPhone}. Please report any spam or suspicious calling activity.`,
        'PHONE',
        language
      );
      result.extractedEntities.phones.push(targetPhone);
    } else if (type === 'UPI' || (upi && !text)) {
      const targetUpi = upi || text;
      result = await ScamShieldScanner.scanText(
        `Suspect UPI payment collect address: ${targetUpi}. Claiming lottery or electricity refund.`,
        'UPI',
        language
      );
      result.extractedEntities.upiIds.push(targetUpi);
    } else {
      if (!text || !text.trim()) {
        return NextResponse.json({ error: 'Content text is required' }, { status: 400 });
      }
      result = await ScamShieldScanner.scanText(text, type, language);
    }

    return NextResponse.json({
      success: true,
      mode: type,
      result,
    });
  } catch (error: any) {
    return NextResponse.json({ error: error.message || 'Analysis failed' }, { status: 500 });
  }
}
