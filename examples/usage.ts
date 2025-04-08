// Example usage of the Passflow SDK

import { Passflow, PassflowConfig, PassflowEvent } from '../lib';

// Configuration
const config: PassflowConfig = {
  url: 'https://api.passflow.example',
  appId: 'my-app-id',
  parseQueryParams: true,
  createTenantForNewUser: true,
};

// Initialize SDK
const passflow = new Passflow(config);

// Subscribe to authentication events
passflow.subscribe({
  onAuthChange: (eventType, source) => {
    console.log(`Auth event: ${eventType}`);

    switch (eventType) {
      case PassflowEvent.SignIn:
        console.log('User signed in successfully');
        break;
      case PassflowEvent.SignOut:
        console.log('User signed out');
        break;
      case PassflowEvent.Error:
        // Check if source is an ErrorPayload before accessing error property
        if (source && 'error' in source) {
          console.error('Authentication error:', source.error);
        } else {
          console.error('Authentication error occurred');
        }
        break;
    }
  },
});

// Example: Sign in with email/password
async function signInWithEmailPassword() {
  try {
    const response = await passflow.signIn({
      email: 'user@example.com',
      password: 'securePassword123',
    });

    console.log('Signed in successfully, tokens:', response);

    // Check if the user is authenticated
    const isAuthenticated = passflow.isAuthenticated();
    console.log('Is authenticated:', isAuthenticated);

    // Get user passkeys
    const passkeys = await passflow.getUserPasskeys();
    console.log('User passkeys:', passkeys);
  } catch (error) {
    console.error('Sign-in failed:', error);
  }
}

// Example: Create tenant and invite users
async function manageTenantAndInvitations() {
  try {
    // Create a new tenant
    const tenant = await passflow.createTenant('My Organization');
    console.log('Created tenant:', tenant);

    // Create invitation link
    const inviteLink = await passflow.requestInviteLink({
      email: 'newuser@example.com',
      role: 'member',
      send_to_email: true,
    });

    console.log('Invitation link:', inviteLink.link);

    // List active invitations
    const invitationsResponse = await passflow.getInvitations({ tenantID: 'your-tenant-id' });
    console.log('Active invitations:', invitationsResponse.invitations);
    console.log('Next page:', invitationsResponse.nextPageSkip);
  } catch (error) {
    console.error('Tenant management failed:', error);
  }
}

// Example: Sign out
async function signOut() {
  try {
    await passflow.logOut();
    console.log('Signed out successfully');
  } catch (error) {
    console.error('Sign-out failed:', error);
  }
}

// Usage
if (window.location.search.includes('action=signin')) {
  signInWithEmailPassword();
} else if (window.location.search.includes('action=manage')) {
  manageTenantAndInvitations();
} else if (window.location.search.includes('action=signout')) {
  signOut();
}
