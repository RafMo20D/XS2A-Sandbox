import { Component, OnInit } from '@angular/core';

@Component({
  selector: 'app-emb-consent-auth-post',
  templateUrl: './emb-consent-auth-post.component.html',
  styleUrls: ['./emb-consent-auth-post.component.scss'],
})
export class EmbConsentAuthPostComponent implements OnInit {
  activeSegment = 'documentation';
  headers: object = {};
  body: object = {};

  constructor() {
    this.init();
  }

  init() {
    this.headers = {
      'X-Request-ID': '2f77a125-aa7a-45c0-b414-cea25a116035',
      'TPP-Explicit-Authorisation-Preferred': 'true',
      'PSU-ID': 'YOUR_USER_LOGIN',
      'PSU-IP-Address': '1.1.1.1',
    };
  }

  changeSegment(segment) {
    this.activeSegment = segment;
  }

  ngOnInit() {}
}
