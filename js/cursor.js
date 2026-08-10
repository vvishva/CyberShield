/**
 * CyberShield AI — Premium Hover Interaction
 * Adds a subtle spotlight effect to cards based on mouse position.
 * Respects prefers-reduced-motion and touch devices.
 */

(function() {
  // Respect accessibility: skip if user prefers reduced motion
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

  // Skip on mobile/touch devices
  if ('ontouchstart' in window || navigator.maxTouchPoints > 0) return;

  const handleMouseMove = e => {
    const cards = document.querySelectorAll('.glass-card, .stat-card');
    
    for (const card of cards) {
      const rect = card.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;

      card.style.setProperty('--mouse-x', `${x}px`);
      card.style.setProperty('--mouse-y', `${y}px`);
    }
  };

  document.body.addEventListener('mousemove', handleMouseMove);
})();
