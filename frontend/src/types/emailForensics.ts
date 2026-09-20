export type AuthenticationVerdict =
  | 'PASS'
  | 'FAIL'
  | 'SOFTFAIL'
  | 'NEUTRAL'
  | 'NONE'
  | 'TEMPERROR'
  | 'PERMERROR'
  | 'UNKNOWN'
  | 'NOT_AVAILABLE';

export interface AuthenticationResult {
  spf: AuthenticationVerdict;
  spf_detail?: string;
  dkim: AuthenticationVerdict;
  dkim_detail?: string;
  dmarc: AuthenticationVerdict;
  dmarc_detail?: string;
  raw_header?: string;
}

export interface ReceivedHop {
  hop: number;
  source: string;
  from_host?: string;
  by_host?: string;
  ip?: string;
  protocol?: string;
  timestamp?: string;
  raw: string;
}

export interface ExtractedIP {
  ip: string;
  source: string;
  header_index?: number;
  context: string;
}

export interface ExtractedURL {
  url: string;
  normalized_url: string;
  scheme: string;
  domain: string;
  port?: number;
  path: string;
  query: string;
  source: string;
}

export interface ExtractedDomain {
  domain: string;
  source_urls: string[];
  occurrence_count: number;
}

export interface AttachmentMetadata {
  filename: string;
  extension: string;
  mime_type: string;
  size_bytes: number;
  sha256: string;
  content_disposition?: string;
}

export interface BodyAnalysis {
  has_html: boolean;
  has_plain_text: boolean;
  character_count: number;
  word_count: number;
  line_count: number;
  link_count: number;
  attachment_count: number;
  normalized_text_preview: string;
}

export interface EmailMetadata {
  from_address: string;
  to_addresses: string[];
  cc_addresses: string[];
  bcc_addresses: string[];
  reply_to?: string;
  return_path?: string;
  subject: string;
  date?: string;
  message_id?: string;
  mime_version?: string;
  content_type?: string;
  raw_headers_count: number;
}

export interface EmailForensicResult {
  investigation_id: string;
  sha256_digest: string;
  file_name: string;
  file_size_bytes: number;
  metadata: EmailMetadata;
  authentication: AuthenticationResult;
  received_chain: ReceivedHop[];
  ip_addresses: ExtractedIP[];
  urls: ExtractedURL[];
  domains: ExtractedDomain[];
  attachments: AttachmentMetadata[];
  body_analysis: BodyAnalysis;
  warnings: string[];
  analyzed_at: string;
}
