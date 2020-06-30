import { Component, OnInit } from '@angular/core';
import { UserTO } from '../../api/models/user-to';
import { CurrentUserService } from '../../common/services/current-user.service';

@Component({
  selector: 'app-user-profile',
  templateUrl: './user-profile.component.html',
  styleUrls: ['./user-profile.component.scss'],
})
export class UserProfileComponent implements OnInit {
  public obaUser: UserTO;

  constructor(private currentUserService: CurrentUserService) {}

  ngOnInit() {
    this.getUserInfo();
  }

  public getUserInfo() {
    this.currentUserService.getCurrentUser().subscribe((data) => {
      if (data.body !== undefined && data.body !== null) {
        return (this.obaUser = data.body);
      }
    });
  }
}
