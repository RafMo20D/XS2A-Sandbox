import { TestBed } from '@angular/core/testing';

import { CertificateDownloadService } from './certificate-download.service';

describe('CertificateDownloadService', () => {
  beforeEach(() => TestBed.configureTestingModule({}));

  it('should be created', () => {
    const service: CertificateDownloadService = TestBed.get(CertificateDownloadService);
    expect(service).toBeTruthy();
  });
});
