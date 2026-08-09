/**
 * CyberShield AI — Premium Cybersecurity Cursor Animation
 * Lightweight canvas-based glowing trail effect.
 * Respects prefers-reduced-motion for accessibility.
 */

(function() {
  // Respect accessibility: skip if user prefers reduced motion
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

  // Skip on mobile/touch devices
  if ('ontouchstart' in window || navigator.maxTouchPoints > 0) return;

  const canvas = document.createElement('canvas');
  canvas.id = 'cursor-canvas';
  canvas.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:99999;';
  document.body.appendChild(canvas);

  const ctx = canvas.getContext('2d');
  let width, height;
  let mouseX = -100, mouseY = -100;
  let particles = [];
  let animFrame;

  function resize() {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
  }
  resize();
  window.addEventListener('resize', resize);

  // Track mouse position
  document.addEventListener('mousemove', (e) => {
    mouseX = e.clientX;
    mouseY = e.clientY;
  });

  // Particle class
  class Particle {
    constructor(x, y) {
      this.x = x;
      this.y = y;
      this.size = Math.random() * 3 + 1;
      this.life = 1.0;
      this.decay = Math.random() * 0.03 + 0.015;
      this.vx = (Math.random() - 0.5) * 0.8;
      this.vy = (Math.random() - 0.5) * 0.8;
    }
    update() {
      this.x += this.vx;
      this.y += this.vy;
      this.life -= this.decay;
    }
    draw() {
      if (this.life <= 0) return;
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.size * this.life, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(0, 212, 255, ${this.life * 0.5})`;
      ctx.fill();
    }
  }

  let frameCount = 0;

  function animate() {
    animFrame = requestAnimationFrame(animate);
    ctx.clearRect(0, 0, width, height);

    // Only spawn particles every other frame for performance
    frameCount++;
    if (frameCount % 2 === 0 && mouseX > 0 && mouseY > 0) {
      particles.push(new Particle(mouseX, mouseY));
    }

    // Cap particles at 40 max
    if (particles.length > 40) {
      particles = particles.slice(-40);
    }

    for (let i = particles.length - 1; i >= 0; i--) {
      particles[i].update();
      particles[i].draw();
      if (particles[i].life <= 0) {
        particles.splice(i, 1);
      }
    }

    // Draw soft glow at cursor
    if (mouseX > 0 && mouseY > 0) {
      const gradient = ctx.createRadialGradient(mouseX, mouseY, 0, mouseX, mouseY, 18);
      gradient.addColorStop(0, 'rgba(0, 212, 255, 0.15)');
      gradient.addColorStop(1, 'rgba(0, 212, 255, 0)');
      ctx.beginPath();
      ctx.arc(mouseX, mouseY, 18, 0, Math.PI * 2);
      ctx.fillStyle = gradient;
      ctx.fill();
    }
  }

  animate();

  // Clean up when page is hidden (save battery)
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      cancelAnimationFrame(animFrame);
    } else {
      animate();
    }
  });
})();
