/**
 * CyberShield - Profile & User Preferences Controller
 */

document.addEventListener('DOMContentLoaded', () => {
  const profileForm = document.getElementById('profile-form');
  const tfaToggle = document.getElementById('2fa-toggle');

  // Load existing profile details
  const user = getUser();
  const nameInput = document.getElementById('profile-username');
  const emailInput = document.getElementById('profile-email');
  if (nameInput) nameInput.value = user.username || '';
  if (emailInput) emailInput.value = user.email || '';

  if (profileForm) {
    profileForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = nameInput.value.trim();
      const twoFactorEnabled = tfaToggle ? tfaToggle.checked : false;

      try {
        const res = await apiRequest('/user/profile', 'PUT', { username, twoFactorEnabled });
        setUser({ ...user, username, twoFactorEnabled }, true);
        showToast('Profile preferences updated successfully!', 'success');
      } catch (err) {
        setUser({ ...user, username, twoFactorEnabled }, true);
        showToast('Offline Mode: Profile preferences saved.', 'success');
      }
    });
  }
});
