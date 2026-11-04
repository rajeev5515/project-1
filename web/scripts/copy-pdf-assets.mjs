// Copy pdf.js standard font data into public/ so it is served from our own
// origin (CSP default-src 'self'); without it, PDFs using the 14 standard
// fonts (Helvetica, Times...) render with a wrong fallback face.
import { cpSync, mkdirSync } from 'node:fs';
const dest = new URL('../public/pdfjs/standard_fonts/', import.meta.url);
mkdirSync(dest, { recursive: true });
cpSync(new URL('../node_modules/pdfjs-dist/standard_fonts/', import.meta.url), dest, { recursive: true });
console.log('pdf.js standard fonts copied');
