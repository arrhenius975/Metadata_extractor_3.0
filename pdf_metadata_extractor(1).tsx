import React, { useState } from 'react';
import { FileText, Search, Download, AlertCircle, CheckCircle, Info, File } from 'lucide-react';
import * as mammoth from 'mammoth';

const UniversalMetadataExtractor = () => {
  const [metadata, setMetadata] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [fileName, setFileName] = useState('');
  const [fileType, setFileType] = useState('');

  const extractPDFMetadata = async (arrayBuffer, textContent, file) => {
    const result = {
      basic: {},
      technical: {},
      security: {},
      forensics: {},
      streams: [],
      objects: [],
      suspicious: [],
      rawData: {}
    };

    // Basic PDF validation
    if (!textContent.startsWith('%PDF-')) {
      throw new Error('Invalid PDF file - missing PDF header');
    }

    // Extract PDF version
    const versionMatch = textContent.match(/%PDF-(\d+\.\d+)/);
    result.basic.version = versionMatch ? versionMatch[1] : 'Unknown';

    // Extract standard metadata
    const infoObj = textContent.match(/\/Info\s+(\d+)\s+\d+\s+R/);
    if (infoObj) {
      const objNum = infoObj[1];
      const objPattern = new RegExp(`${objNum}\\s+\\d+\\s+obj([\\s\\S]*?)endobj`);
      const objMatch = textContent.match(objPattern);
      
      if (objMatch) {
        const metadata = objMatch[1];
        result.basic.title = extractField(metadata, 'Title');
        result.basic.author = extractField(metadata, 'Author');
        result.basic.subject = extractField(metadata, 'Subject');
        result.basic.keywords = extractField(metadata, 'Keywords');
        result.basic.creator = extractField(metadata, 'Creator');
        result.basic.producer = extractField(metadata, 'Producer');
        result.basic.creationDate = parseDate(extractField(metadata, 'CreationDate'));
        result.basic.modDate = parseDate(extractField(metadata, 'ModDate'));
      }
    }

    // Extract XMP metadata
    const xmpMatch = textContent.match(/<x:xmpmeta[\s\S]*?<\/x:xmpmeta>/);
    if (xmpMatch) {
      result.technical.hasXMP = true;
      result.technical.xmpData = xmpMatch[0].substring(0, 500) + '...';
    }

    // Count objects
    const objMatches = textContent.match(/\d+\s+\d+\s+obj/g);
    result.technical.totalObjects = objMatches ? objMatches.length : 0;

    // Detect encryption
    result.security.encrypted = textContent.includes('/Encrypt');
    if (result.security.encrypted) {
      const encryptMatch = textContent.match(/\/Filter\s*\/(\w+)/);
      result.security.encryptionType = encryptMatch ? encryptMatch[1] : 'Unknown';
    }

    // Detect JavaScript
    const jsCount = (textContent.match(/\/JavaScript|\/JS/g) || []).length;
    result.security.containsJavaScript = jsCount > 0;
    result.security.javascriptCount = jsCount;
    if (jsCount > 0) {
      result.suspicious.push({
        type: 'JavaScript Detected',
        severity: 'Medium',
        description: `Found ${jsCount} JavaScript references`
      });
    }

    // Detect embedded files
    const embeddedFiles = (textContent.match(/\/EmbeddedFile/g) || []).length;
    result.security.embeddedFiles = embeddedFiles;
    if (embeddedFiles > 0) {
      result.suspicious.push({
        type: 'Embedded Files',
        severity: 'Low',
        description: `Found ${embeddedFiles} embedded file(s)`
      });
    }

    // Detect forms and actions
    const acroForm = textContent.includes('/AcroForm');
    result.security.containsForms = acroForm;
    
    const actions = (textContent.match(/\/AA\s*<<|\/OpenAction/g) || []).length;
    result.security.automaticActions = actions;
    if (actions > 0) {
      result.suspicious.push({
        type: 'Automatic Actions',
        severity: 'High',
        description: `Found ${actions} automatic action(s) - could execute on open`
      });
    }

    // Detect launch actions
    const launchActions = (textContent.match(/\/Launch/g) || []).length;
    if (launchActions > 0) {
      result.suspicious.push({
        type: 'Launch Actions',
        severity: 'Critical',
        description: `Found ${launchActions} launch action(s) - can execute external programs`
      });
    }

    // Detect URI/URLs
    const uriMatches = textContent.match(/\/URI\s*\(([^)]+)\)/g);
    if (uriMatches) {
      result.security.externalLinks = uriMatches.length;
      result.forensics.urls = uriMatches.slice(0, 10).map(u => 
        u.replace(/\/URI\s*\(/, '').replace(/\)$/, '')
      );
    }

    // Extract streams
    const streamMatches = textContent.match(/stream\n([\s\S]*?)\nendstream/g);
    result.technical.totalStreams = streamMatches ? streamMatches.length : 0;
    
    if (streamMatches) {
      streamMatches.slice(0, 5).forEach((stream, idx) => {
        const streamData = stream.replace(/^stream\n/, '').replace(/\nendstream$/, '');
        result.streams.push({
          index: idx,
          length: streamData.length,
          preview: streamData.substring(0, 100),
          isPrintable: /^[\x20-\x7E\s]*$/.test(streamData.substring(0, 100))
        });
      });
    }

    // File size analysis
    result.forensics.fileSize = file.size;
    result.forensics.fileSizeHuman = formatBytes(file.size);

    // Check for linearization
    result.technical.linearized = textContent.includes('/Linearized');

    // Extract page count
    const pageMatch = textContent.match(/\/Type\s*\/Pages[\s\S]*?\/Count\s+(\d+)/);
    result.technical.pageCount = pageMatch ? parseInt(pageMatch[1]) : 'Unknown';

    // Check for incremental updates
    const xrefMatches = textContent.match(/%%EOF/g);
    result.forensics.incrementalUpdates = xrefMatches ? xrefMatches.length - 1 : 0;
    if (result.forensics.incrementalUpdates > 0) {
      result.suspicious.push({
        type: 'Incremental Updates',
        severity: 'Info',
        description: `Document has ${result.forensics.incrementalUpdates} incremental update(s) - may indicate modifications`
      });
    }

    // Extract object references
    const objRefs = textContent.match(/\d+\s+\d+\s+obj/g);
    if (objRefs) {
      result.objects = objRefs.slice(0, 20).map(ref => ref.replace(/\s+obj$/, ''));
    }

    // Check for filters
    const filters = ['ASCIIHexDecode', 'ASCII85Decode', 'LZWDecode', 'FlateDecode', 'RunLengthDecode', 'CCITTFaxDecode', 'JBIG2Decode', 'DCTDecode', 'JPXDecode', 'Crypt'];
    result.technical.filtersUsed = [];
    filters.forEach(filter => {
      if (textContent.includes(`/${filter}`)) {
        result.technical.filtersUsed.push(filter);
      }
    });

    // Raw hex dump
    const uint8Array = new Uint8Array(arrayBuffer);
    result.rawData.hexDump = Array.from(uint8Array.slice(0, 512))
      .map(b => b.toString(16).padStart(2, '0'))
      .join(' ');
    
    result.rawData.header = textContent.substring(0, 200);

    return result;
  };

  const extractImageMetadata = async (arrayBuffer, file) => {
    const uint8Array = new Uint8Array(arrayBuffer);
    const result = {
      basic: {},
      technical: {},
      exif: {},
      gps: {},
      forensics: {},
      suspicious: [],
      rawData: {}
    };

    result.forensics.fileSize = file.size;
    result.forensics.fileSizeHuman = formatBytes(file.size);
    result.basic.fileName = file.name;
    result.basic.mimeType = file.type;

    // Detect image type
    const header = Array.from(uint8Array.slice(0, 4));
    if (header[0] === 0xFF && header[1] === 0xD8) {
      result.basic.format = 'JPEG';
      await extractJPEGMetadata(uint8Array, result);
    } else if (header[0] === 0x89 && header[1] === 0x50 && header[2] === 0x4E && header[3] === 0x47) {
      result.basic.format = 'PNG';
      await extractPNGMetadata(uint8Array, result);
    }

    // Hex dump
    result.rawData.hexDump = Array.from(uint8Array.slice(0, 512))
      .map(b => b.toString(16).padStart(2, '0'))
      .join(' ');

    return result;
  };

  const extractJPEGMetadata = async (data, result) => {
    let offset = 2; // Skip SOI marker

    while (offset < data.length) {
      if (data[offset] !== 0xFF) break;
      
      const marker = data[offset + 1];
      const length = (data[offset + 2] << 8) | data[offset + 3];

      // APP1 - EXIF data
      if (marker === 0xE1) {
        const exifData = data.slice(offset + 4, offset + 2 + length);
        parseEXIF(exifData, result);
      }

      // APP0 - JFIF
      if (marker === 0xE0) {
        result.technical.hasJFIF = true;
      }

      // COM - Comment
      if (marker === 0xFE) {
        const comment = new TextDecoder().decode(data.slice(offset + 4, offset + 2 + length));
        result.basic.comment = comment;
      }

      // SOF - Start of Frame (image dimensions)
      if (marker >= 0xC0 && marker <= 0xCF && marker !== 0xC4 && marker !== 0xC8 && marker !== 0xCC) {
        result.technical.height = (data[offset + 5] << 8) | data[offset + 6];
        result.technical.width = (data[offset + 7] << 8) | data[offset + 8];
        result.technical.colorComponents = data[offset + 9];
      }

      offset += 2 + length;
    }
  };

  const parseEXIF = (data, result) => {
    try {
      // Check for EXIF header
      const exifHeader = String.fromCharCode(...data.slice(0, 6));
      if (exifHeader !== 'Exif\0\0') return;

      const exifData = data.slice(6);
      const littleEndian = exifData[0] === 0x49;

      const getUint16 = (offset) => {
        return littleEndian 
          ? exifData[offset] | (exifData[offset + 1] << 8)
          : (exifData[offset] << 8) | exifData[offset + 1];
      };

      const getUint32 = (offset) => {
        return littleEndian
          ? exifData[offset] | (exifData[offset + 1] << 8) | (exifData[offset + 2] << 16) | (exifData[offset + 3] << 24)
          : (exifData[offset] << 24) | (exifData[offset + 1] << 16) | (exifData[offset + 2] << 8) | exifData[offset + 3];
      };

      const ifdOffset = getUint32(4);
      const numEntries = getUint16(ifdOffset);

      result.technical.hasEXIF = true;

      // Parse IFD entries
      for (let i = 0; i < numEntries; i++) {
        const entryOffset = ifdOffset + 2 + (i * 12);
        const tag = getUint16(entryOffset);
        const type = getUint16(entryOffset + 2);
        const count = getUint32(entryOffset + 4);
        const valueOffset = getUint32(entryOffset + 8);

        // Common EXIF tags
        const tags = {
          0x010F: 'Make',
          0x0110: 'Model',
          0x0112: 'Orientation',
          0x011A: 'XResolution',
          0x011B: 'YResolution',
          0x0131: 'Software',
          0x0132: 'DateTime',
          0x013B: 'Artist',
          0x8298: 'Copyright',
          0x829A: 'ExposureTime',
          0x829D: 'FNumber',
          0x8822: 'ExposureProgram',
          0x8827: 'ISO',
          0x9003: 'DateTimeOriginal',
          0x9004: 'DateTimeDigitized',
          0x920A: 'FocalLength',
          0xA002: 'PixelXDimension',
          0xA003: 'PixelYDimension',
          0xA434: 'LensModel'
        };

        if (tags[tag]) {
          let value;
          if (type === 2) { // ASCII
            const strOffset = count > 4 ? valueOffset : entryOffset + 8;
            value = String.fromCharCode(...exifData.slice(strOffset, strOffset + count - 1));
          } else if (type === 3) { // SHORT
            value = count > 2 ? getUint16(valueOffset) : getUint16(entryOffset + 8);
          } else if (type === 4) { // LONG
            value = valueOffset;
          }
          
          result.exif[tags[tag]] = value;
        }

        // GPS data
        if (tag === 0x8825) { // GPS IFD pointer
          parseGPSData(exifData, valueOffset, result, getUint16, getUint32, littleEndian);
        }
      }

      // Check for potential steganography indicators
      if (result.exif.Software && result.exif.Software.toLowerCase().includes('steg')) {
        result.suspicious.push({
          type: 'Steganography Tool Detected',
          severity: 'High',
          description: `Software field contains: ${result.exif.Software}`
        });
      }

    } catch (e) {
      result.exif.parseError = e.message;
    }
  };

  const parseGPSData = (data, offset, result, getUint16, getUint32, littleEndian) => {
    try {
      const numEntries = getUint16(offset);
      result.gps = {};

      for (let i = 0; i < numEntries; i++) {
        const entryOffset = offset + 2 + (i * 12);
        const tag = getUint16(entryOffset);
        const type = getUint16(entryOffset + 2);
        const count = getUint32(entryOffset + 4);
        const valueOffset = getUint32(entryOffset + 8);

        const gpsTags = {
          0x0001: 'GPSLatitudeRef',
          0x0002: 'GPSLatitude',
          0x0003: 'GPSLongitudeRef',
          0x0004: 'GPSLongitude',
          0x0005: 'GPSAltitudeRef',
          0x0006: 'GPSAltitude',
          0x0007: 'GPSTimeStamp',
          0x001D: 'GPSDateStamp'
        };

        if (gpsTags[tag]) {
          let value;
          if (type === 2) { // ASCII
            const strOffset = count > 4 ? valueOffset : entryOffset + 8;
            value = String.fromCharCode(...data.slice(strOffset, strOffset + count - 1));
          }
          result.gps[gpsTags[tag]] = value || valueOffset;
        }
      }

      if (Object.keys(result.gps).length > 0) {
        result.suspicious.push({
          type: 'GPS Location Data Found',
          severity: 'Medium',
          description: 'Image contains embedded GPS coordinates'
        });
      }
    } catch (e) {
      // GPS parsing failed
    }
  };

  const extractPNGMetadata = async (data, result) => {
    let offset = 8; // Skip PNG signature

    result.technical.hasPNG = true;
    const chunks = [];

    while (offset < data.length) {
      const length = (data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];
      const type = String.fromCharCode(data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]);
      const chunkData = data.slice(offset + 8, offset + 8 + length);

      chunks.push({ type, length });

      // IHDR - Image header
      if (type === 'IHDR') {
        result.technical.width = (chunkData[0] << 24) | (chunkData[1] << 16) | (chunkData[2] << 8) | chunkData[3];
        result.technical.height = (chunkData[4] << 24) | (chunkData[5] << 16) | (chunkData[6] << 8) | chunkData[7];
        result.technical.bitDepth = chunkData[8];
        result.technical.colorType = chunkData[9];
        result.technical.compressionMethod = chunkData[10];
        result.technical.filterMethod = chunkData[11];
        result.technical.interlaceMethod = chunkData[12];
      }

      // tEXt - Text data
      if (type === 'tEXt') {
        const text = new TextDecoder().decode(chunkData);
        const nullIndex = text.indexOf('\0');
        if (nullIndex !== -1) {
          const key = text.substring(0, nullIndex);
          const value = text.substring(nullIndex + 1);
          if (!result.basic.textChunks) result.basic.textChunks = {};
          result.basic.textChunks[key] = value;
        }
      }

      // zTXt - Compressed text
      if (type === 'zTXt') {
        result.suspicious.push({
          type: 'Compressed Text Chunk',
          severity: 'Low',
          description: 'PNG contains compressed text data (potential hidden data)'
        });
      }

      // tRNS - Transparency
      if (type === 'tRNS') {
        result.technical.hasTransparency = true;
      }

      // Check for unusual chunks
      const criticalChunk = type[0] === type[0].toUpperCase();
      if (!criticalChunk && !['tEXt', 'zTXt', 'iTXt', 'tIME', 'pHYs', 'gAMA', 'cHRM', 'sRGB', 'iCCP', 'bKGD', 'tRNS'].includes(type)) {
        result.suspicious.push({
          type: 'Unusual Ancillary Chunk',
          severity: 'Medium',
          description: `Found non-standard chunk: ${type}`
        });
      }

      offset += 12 + length;

      if (type === 'IEND') break;
    }

    result.technical.totalChunks = chunks.length;
    result.technical.chunkTypes = [...new Set(chunks.map(c => c.type))].join(', ');
  };

  const extractDOCXMetadata = async (arrayBuffer, file) => {
    const result = {
      basic: {},
      technical: {},
      forensics: {},
      suspicious: [],
      content: {},
      rawData: {}
    };

    result.forensics.fileSize = file.size;
    result.forensics.fileSizeHuman = formatBytes(file.size);
    result.basic.fileName = file.name;
    result.basic.format = 'DOCX';

    try {
      // Extract text content
      const docResult = await mammoth.extractRawText({ arrayBuffer });
      result.content.textPreview = docResult.value.substring(0, 500);
      result.content.characterCount = docResult.value.length;
      result.content.wordCount = docResult.value.split(/\s+/).filter(w => w.length > 0).length;

      // Check for potential hidden text (very short visible content but large file)
      if (result.content.characterCount < 100 && file.size > 50000) {
        result.suspicious.push({
          type: 'Suspicious Size Ratio',
          severity: 'Medium',
          description: 'Large file size with minimal visible content - may contain hidden data'
        });
      }

      // DOCX is a ZIP file - we can parse it
      const uint8Array = new Uint8Array(arrayBuffer);
      
      // Check ZIP signature
      if (uint8Array[0] === 0x50 && uint8Array[1] === 0x4B) {
        result.technical.isValidZip = true;
        
        // Count embedded files
        const centralDirMatches = arrayBuffer.byteLength;
        result.technical.estimatedFileCount = (new TextDecoder().decode(uint8Array).match(/PK\x01\x02/g) || []).length;

        // Check for macros
        const textContent = new TextDecoder().decode(uint8Array);
        if (textContent.includes('vbaProject.bin') || textContent.includes('word/vbaProject')) {
          result.suspicious.push({
            type: 'VBA Macros Detected',
            severity: 'High',
            description: 'Document contains VBA macros - potential security risk'
          });
          result.technical.containsMacros = true;
        }

        // Check for external links
        const externalLinks = (textContent.match(/https?:\/\/[^\s<>"]+/g) || []).slice(0, 10);
        if (externalLinks.length > 0) {
          result.suspicious.push({
            type: 'External Links Found',
            severity: 'Low',
            description: `Document contains ${externalLinks.length} external links`
          });
          result.forensics.externalLinks = externalLinks;
        }

        // Check for embedded objects
        if (textContent.includes('embeddings')) {
          result.technical.hasEmbeddedObjects = true;
          result.suspicious.push({
            type: 'Embedded Objects',
            severity: 'Medium',
            description: 'Document contains embedded objects'
          });
        }

        // Extract core properties if present
        const corePropsMatch = textContent.match(/<dc:creator>([^<]+)<\/dc:creator>/);
        if (corePropsMatch) result.basic.creator = corePropsMatch[1];

        const titleMatch = textContent.match(/<dc:title>([^<]+)<\/dc:title>/);
        if (titleMatch) result.basic.title = titleMatch[1];

        const createdMatch = textContent.match(/<dcterms:created[^>]*>([^<]+)<\/dcterms:created>/);
        if (createdMatch) result.basic.created = createdMatch[1];

        const modifiedMatch = textContent.match(/<dcterms:modified[^>]*>([^<]+)<\/dcterms:modified>/);
        if (modifiedMatch) result.basic.modified = modifiedMatch[1];

        const lastModifiedByMatch = textContent.match(/<cp:lastModifiedBy>([^<]+)<\/cp:lastModifiedBy>/);
        if (lastModifiedByMatch) result.basic.lastModifiedBy = lastModifiedByMatch[1];

        const revisionMatch = textContent.match(/<cp:revision>([^<]+)<\/cp:revision>/);
        if (revisionMatch) result.basic.revision = revisionMatch[1];
      }

      // Hex dump
      result.rawData.hexDump = Array.from(uint8Array.slice(0, 512))
        .map(b => b.toString(16).padStart(2, '0'))
        .join(' ');

    } catch (e) {
      result.forensics.error = e.message;
    }

    return result;
  };

  const extractField = (text, field) => {
    const regex = new RegExp(`/${field}\\s*\\(([^)]*)\\)|/${field}\\s*<([^>]*)>|/${field}\\s*([^/\\s]+)`);
    const match = text.match(regex);
    if (match) {
      return (match[1] || match[2] || match[3] || '').trim();
    }
    return null;
  };

  const parseDate = (dateStr) => {
    if (!dateStr) return null;
    const match = dateStr.match(/D:(\d{4})(\d{2})(\d{2})(\d{2})?(\d{2})?(\d{2})?/);
    if (match) {
      const [, year, month, day, hour = '00', min = '00', sec = '00'] = match;
      return `${year}-${month}-${day} ${hour}:${min}:${sec}`;
    }
    return dateStr;
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  const handleFileChange = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setLoading(true);
    setError(null);
    setFileName(file.name);

    try {
      const arrayBuffer = await file.arrayBuffer();
      let result;

      if (file.type === 'application/pdf' || file.name.endsWith('.pdf')) {
        setFileType('PDF');
        const textContent = new TextDecoder('latin1').decode(new Uint8Array(arrayBuffer));
        result = await extractPDFMetadata(arrayBuffer, textContent, file);
      } else if (file.type.startsWith('image/') || /\.(jpg|jpeg|png)$/i.test(file.name)) {
        setFileType('IMAGE');
        result = await extractImageMetadata(arrayBuffer, file);
      } else if (file.type === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' || file.name.endsWith('.docx')) {
        setFileType('DOCX');
        result = await extractDOCXMetadata(arrayBuffer, file);
      } else {
        throw new Error('Unsupported file type. Please upload PDF, Image (JPG/PNG), or DOCX files.');
      }

      setMetadata(result);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const exportJSON = () => {
    const dataStr = JSON.stringify(metadata, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${fileName}_metadata.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'Critical': return 'text-red-600 bg-red-50 border-red-200';
      case 'High': return 'text-orange-600 bg-orange-50 border-orange-200';
      case 'Medium': return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      case 'Low': return 'text-blue-600 bg-blue-50 border-blue-200';
      default: return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const renderPDFResults = () => (
    <>
      {metadata.suspicious.length > 0 && (
        <div className="bg-slate-800 rounded-lg p-6">
          <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
            <AlertCircle className="w-6 h-6 text-red-400" />
            Security Alerts
          </h3>
          <div className="space-y-3">
            {metadata.suspicious.map((item, idx) => (
              <div key={idx} className={`p-4 rounded-lg border ${getSeverityColor(item.severity)}`}>
                <div className="flex items-start gap-3">
                  <AlertCircle className="w-5 h-5 mt-0.5 flex-shrink-0" />
                  <div>
                    <div className="font-semibold">{item.type} - {item.severity}</div>
                    <div className="text-sm mt-1">{item.description}</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="bg-slate-800 rounded-lg p-6">
        <h3 className="text-xl font-bold text-white mb-4">Basic Metadata</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {Object.entries(metadata.basic).map(([key, value]) => (
            value && (
              <div key={key}>
                <div className="text-sm text-slate