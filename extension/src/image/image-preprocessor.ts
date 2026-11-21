/**
 * ScamShield — Image Preprocessing Engine for Robust OCR
 *
 * Implements intelligent preprocessing to enhance OCR accuracy across
 * noisy, low-contrast, compressed, or high-resolution screenshots.
 *
 * Capabilities:
 * - Proportional dimension normalization (bounds between 400px and 1800px)
 * - Grayscale luminance conversion (ITU-R BT.601)
 * - Contrast stretching / Dynamic histogram normalization
 * - Otsu-based adaptive binarization (for dark and light mode screenshots)
 * - Safe canvas abstraction supporting both browser and mock/test environments
 */

export interface PreprocessingOptions {
  maxDimension?: number;
  minDimension?: number;
  enhanceContrast?: boolean;
  binarize?: boolean;
}

export interface PreprocessingResult {
  preprocessedDataUrl: string;
  originalWidth: number;
  originalHeight: number;
  processedWidth: number;
  processedHeight: number;
  scalingFactor: number;
  techniquesApplied: string[];
}

export class ImagePreprocessor {
  /**
   * Preprocesses an image data URL for optimal OCR readability
   */
  static async preprocessImage(
    imageDataUrl: string,
    options: PreprocessingOptions = {}
  ): Promise<PreprocessingResult> {
    const maxDim = options.maxDimension || 1600;
    const minDim = options.minDimension || 400;
    const enhanceContrast = options.enhanceContrast !== false;
    const binarize = options.binarize || false;

    const techniques: string[] = [];

    // If running in Node.js test environment without DOM Image/Canvas, return cleanly
    if (typeof window === 'undefined' || typeof document === 'undefined') {
      return {
        preprocessedDataUrl: imageDataUrl,
        originalWidth: 800,
        originalHeight: 600,
        processedWidth: 800,
        processedHeight: 600,
        scalingFactor: 1.0,
        techniquesApplied: ['NODE_PASSTHROUGH'],
      };
    }

    try {
      const img = await this.loadImage(imageDataUrl);
      const origW = img.naturalWidth || img.width;
      const origH = img.naturalHeight || img.height;

      // 1. Calculate optimal scaling while maintaining aspect ratio
      let targetW = origW;
      let targetH = origH;
      let scalingFactor = 1.0;

      const maxCurrentDim = Math.max(origW, origH);
      const minCurrentDim = Math.min(origW, origH);

      if (maxCurrentDim > maxDim) {
        scalingFactor = maxDim / maxCurrentDim;
        targetW = Math.round(origW * scalingFactor);
        targetH = Math.round(origH * scalingFactor);
        techniques.push(`DOWNSCALE_${Math.round(scalingFactor * 100)}%`);
      } else if (minCurrentDim < minDim && minCurrentDim > 0) {
        scalingFactor = Math.min(2.0, minDim / minCurrentDim);
        targetW = Math.round(origW * scalingFactor);
        targetH = Math.round(origH * scalingFactor);
        techniques.push(`UPSCALE_${Math.round(scalingFactor * 100)}%`);
      }

      // 2. Render to 2D Canvas
      const canvas = document.createElement('canvas');
      canvas.width = targetW;
      canvas.height = targetH;
      const ctx = canvas.getContext('2d', { willReadFrequently: true });

      if (!ctx) {
        return {
          preprocessedDataUrl: imageDataUrl,
          originalWidth: origW,
          originalHeight: origH,
          processedWidth: targetW,
          processedHeight: targetH,
          scalingFactor,
          techniquesApplied: ['CANVAS_UNAVAILABLE'],
        };
      }

      ctx.imageSmoothingEnabled = true;
      ctx.imageSmoothingQuality = 'high';
      ctx.drawImage(img, 0, 0, targetW, targetH);

      // 3. Pixel-level enhancements (Grayscale + Dynamic Contrast + Optional Binarization)
      const imgData = ctx.getImageData(0, 0, targetW, targetH);
      const pixels = imgData.data;
      const numPixels = targetW * targetH;

      // Find min and max luminance for contrast stretching
      let minLum = 255;
      let maxLum = 0;
      const luminance = new Uint8ClampedArray(numPixels);

      for (let i = 0, p = 0; i < pixels.length; i += 4, p++) {
        // Standard Rec. 601 Luma
        const lum = Math.round(0.299 * pixels[i] + 0.587 * pixels[i + 1] + 0.114 * pixels[i + 2]);
        luminance[p] = lum;
        if (lum < minLum) minLum = lum;
        if (lum > maxLum) maxLum = lum;
      }

      techniques.push('GRAYSCALE_BT601');

      const lumRange = maxLum - minLum;
      const canStretch = enhanceContrast && lumRange > 20 && lumRange < 240;

      if (canStretch) {
        techniques.push(`CONTRAST_STRETCH_[${minLum}-${maxLum}]`);
      }

      // Optional Otsu threshold calculation
      let threshold = 128;
      if (binarize) {
        threshold = this.calculateOtsuThreshold(luminance);
        techniques.push(`OTSU_THRESHOLD_${threshold}`);
      }

      for (let i = 0, p = 0; i < pixels.length; i += 4, p++) {
        let val = luminance[p];

        // Apply contrast stretch
        if (canStretch) {
          val = Math.round(((val - minLum) / lumRange) * 255);
        }

        // Apply binarization if requested
        if (binarize) {
          val = val >= threshold ? 255 : 0;
        }

        pixels[i] = val;
        pixels[i + 1] = val;
        pixels[i + 2] = val;
        // keep alpha pixels[i + 3] untouched
      }

      ctx.putImageData(imgData, 0, 0);
      const processedDataUrl = canvas.toDataURL('image/png');

      return {
        preprocessedDataUrl: processedDataUrl,
        originalWidth: origW,
        originalHeight: origH,
        processedWidth: targetW,
        processedHeight: targetH,
        scalingFactor,
        techniquesApplied: techniques,
      };
    } catch (err) {
      return {
        preprocessedDataUrl: imageDataUrl,
        originalWidth: 800,
        originalHeight: 600,
        processedWidth: 800,
        processedHeight: 600,
        scalingFactor: 1.0,
        techniquesApplied: [`PREPROCESSING_ERROR: ${err instanceof Error ? err.message : String(err)}`],
      };
    }
  }

  /**
   * Otsu's method for automatic global threshold calculation
   */
  private static calculateOtsuThreshold(luminance: Uint8ClampedArray): number {
    const histogram = new Array(256).fill(0);
    const total = luminance.length;

    for (let i = 0; i < total; i++) {
      histogram[luminance[i]]++;
    }

    let sum = 0;
    for (let t = 0; t < 256; t++) {
      sum += t * histogram[t];
    }

    let sumB = 0;
    let wB = 0;
    let wF = 0;
    let maxVariance = 0;
    let bestThreshold = 128;

    for (let t = 0; t < 256; t++) {
      wB += histogram[t];
      if (wB === 0) continue;
      wF = total - wB;
      if (wF === 0) break;

      sumB += t * histogram[t];
      const mB = sumB / wB;
      const mF = (sum - sumB) / wF;

      const varianceBetween = wB * wF * (mB - mF) * (mB - mF);
      if (varianceBetween > maxVariance) {
        maxVariance = varianceBetween;
        bestThreshold = t;
      }
    }

    return bestThreshold;
  }

  /**
   * Helper to load an HTMLImageElement from a data URL
   */
  private static loadImage(src: string): Promise<HTMLImageElement> {
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.crossOrigin = 'anonymous';
      img.onload = () => resolve(img);
      img.onerror = () => reject(new Error('Failed to load image data URL into element'));
      img.src = src;
    });
  }
}
