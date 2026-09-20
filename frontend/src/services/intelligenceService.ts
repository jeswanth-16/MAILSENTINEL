import { apiClient } from './api';
import {
  DomainIntelligenceResult,
  EmailAddressIntelligenceResult,
  IndicatorCorrelationRequest,
  IndicatorCorrelationResult,
  IPIntelligenceResult,
  InvestigationIntelligenceResult,
  URLIntelligenceResult,
} from '../types/intelligence';

export async function lookupIP(ip: string): Promise<IPIntelligenceResult> {
  return apiClient<IPIntelligenceResult>('/intelligence/ip', {
    method: 'POST',
    body: JSON.stringify({ ip }),
  });
}

export async function lookupDomain(domain: string): Promise<DomainIntelligenceResult> {
  return apiClient<DomainIntelligenceResult>('/intelligence/domain', {
    method: 'POST',
    body: JSON.stringify({ domain }),
  });
}

export async function lookupURL(url: string): Promise<URLIntelligenceResult> {
  return apiClient<URLIntelligenceResult>('/intelligence/url', {
    method: 'POST',
    body: JSON.stringify({ url }),
  });
}

export async function lookupEmail(
  email: string,
  role: string = 'SENDER'
): Promise<EmailAddressIntelligenceResult> {
  return apiClient<EmailAddressIntelligenceResult>('/intelligence/email', {
    method: 'POST',
    body: JSON.stringify({ email, role }),
  });
}

export async function enrichInvestigation(
  investigationId: string,
  ips: string[],
  domains: string[],
  urls: string[],
  emails?: string[]
): Promise<InvestigationIntelligenceResult> {
  return apiClient<InvestigationIntelligenceResult>(
    `/intelligence/investigation/${encodeURIComponent(investigationId)}`,
    {
      method: 'POST',
      body: JSON.stringify({ ips, domains, urls, emails: emails || [] }),
    }
  );
}

export async function correlateIndicators(
  request: IndicatorCorrelationRequest
): Promise<IndicatorCorrelationResult> {
  return apiClient<IndicatorCorrelationResult>('/intelligence/correlate', {
    method: 'POST',
    body: JSON.stringify(request),
  });
}

export async function getInvestigationCorrelation(
  investigationId: string
): Promise<IndicatorCorrelationResult> {
  return apiClient<IndicatorCorrelationResult>(
    `/intelligence/investigation/${encodeURIComponent(investigationId)}/correlation`,
    {
      method: 'GET',
    }
  );
}
