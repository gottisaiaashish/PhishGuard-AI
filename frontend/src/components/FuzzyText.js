/**
 * FuzzyText - High-performance Canvas Fuzzy/Glitch Text Effect
 * Adapted from React Bits (https://reactbits.dev)
 * 
 * Can be initialized on any canvas element or container with full props support:
 * - baseIntensity, hoverIntensity, fuzzRange, fps, direction, glitchMode, clickEffect, gradient
 */

export function mountFuzzyText(containerOrCanvas, options = {}) {
  const {
    text = 'PHISHGUARD AI',
    fontSize = 'clamp(2.2rem, 6vw, 4.5rem)',
    fontWeight = 900,
    fontFamily = 'Inter, sans-serif',
    color = '#00f0ff',
    enableHover = true,
    baseIntensity = 0.18,
    hoverIntensity = 0.55,
    fuzzRange = 25,
    fps = 60,
    direction = 'horizontal',
    transitionDuration = 6,
    clickEffect = true,
    glitchMode = true,
    glitchInterval = 2400,
    glitchDuration = 180,
    gradient = ['#00f0ff', '#6366f1', '#a855f7'],
    letterSpacing = 2,
    className = 'fuzzy-text-canvas'
  } = options;

  let canvas;
  if (containerOrCanvas.tagName === 'CANVAS') {
    canvas = containerOrCanvas;
  } else {
    containerOrCanvas.innerHTML = '';
    canvas = document.createElement('canvas');
    if (className) canvas.className = className;
    containerOrCanvas.appendChild(canvas);
  }

  let animationFrameId;
  let isCancelled = false;
  let glitchTimeoutId;
  let glitchEndTimeoutId;
  let clickTimeoutId;

  const init = async () => {
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const computedFontFamily =
      fontFamily === 'inherit' ? window.getComputedStyle(canvas).fontFamily || 'sans-serif' : fontFamily;

    const fontSizeStr = typeof fontSize === 'number' ? `${fontSize}px` : fontSize;
    const fontString = `${fontWeight} ${fontSizeStr} ${computedFontFamily}`;

    try {
      await document.fonts.load(fontString);
    } catch {
      await document.fonts.ready;
    }
    if (isCancelled) return;

    let numericFontSize;
    if (typeof fontSize === 'number') {
      numericFontSize = fontSize;
    } else {
      const temp = document.createElement('span');
      temp.style.fontSize = fontSize;
      document.body.appendChild(temp);
      const computedSize = window.getComputedStyle(temp).fontSize;
      numericFontSize = parseFloat(computedSize);
      document.body.removeChild(temp);
    }

    const offscreen = document.createElement('canvas');
    const offCtx = offscreen.getContext('2d');
    if (!offCtx) return;

    offCtx.font = `${fontWeight} ${fontSizeStr} ${computedFontFamily}`;
    offCtx.textBaseline = 'alphabetic';

    let totalWidth = 0;
    if (letterSpacing !== 0) {
      for (const char of text) {
        totalWidth += offCtx.measureText(char).width + letterSpacing;
      }
      totalWidth -= letterSpacing;
    } else {
      totalWidth = offCtx.measureText(text).width;
    }

    const metrics = offCtx.measureText(text);
    const actualLeft = metrics.actualBoundingBoxLeft ?? 0;
    const actualRight = letterSpacing !== 0 ? totalWidth : (metrics.actualBoundingBoxRight ?? metrics.width);
    const actualAscent = metrics.actualBoundingBoxAscent ?? numericFontSize;
    const actualDescent = metrics.actualBoundingBoxDescent ?? numericFontSize * 0.2;

    const textBoundingWidth = Math.ceil(letterSpacing !== 0 ? totalWidth : actualLeft + actualRight);
    const tightHeight = Math.ceil(actualAscent + actualDescent);

    const extraWidthBuffer = 12;
    const offscreenWidth = textBoundingWidth + extraWidthBuffer;

    offscreen.width = offscreenWidth;
    offscreen.height = tightHeight;

    const xOffset = extraWidthBuffer / 2;
    offCtx.font = `${fontWeight} ${fontSizeStr} ${computedFontFamily}`;
    offCtx.textBaseline = 'alphabetic';

    if (gradient && Array.isArray(gradient) && gradient.length >= 2) {
      const grad = offCtx.createLinearGradient(0, 0, offscreenWidth, 0);
      gradient.forEach((c, i) => grad.addColorStop(i / (gradient.length - 1), c));
      offCtx.fillStyle = grad;
    } else {
      offCtx.fillStyle = color;
    }

    if (letterSpacing !== 0) {
      let xPos = xOffset;
      for (const char of text) {
        offCtx.fillText(char, xPos, actualAscent);
        xPos += offCtx.measureText(char).width + letterSpacing;
      }
    } else {
      offCtx.fillText(text, xOffset - actualLeft, actualAscent);
    }

    const horizontalMargin = fuzzRange + 20;
    const verticalMargin = direction === 'vertical' || direction === 'both' ? fuzzRange + 10 : 0;
    canvas.width = offscreenWidth + horizontalMargin * 2;
    canvas.height = tightHeight + verticalMargin * 2;
    ctx.translate(horizontalMargin, verticalMargin);

    const interactiveLeft = horizontalMargin + xOffset;
    const interactiveTop = verticalMargin;
    const interactiveRight = interactiveLeft + textBoundingWidth;
    const interactiveBottom = interactiveTop + tightHeight;

    let isHovering = false;
    let isClicking = false;
    let isGlitching = false;
    let currentIntensity = baseIntensity;
    let targetIntensity = baseIntensity;
    let lastFrameTime = 0;
    const frameDuration = 1000 / fps;

    const startGlitchLoop = () => {
      if (!glitchMode || isCancelled) return;
      glitchTimeoutId = setTimeout(() => {
        if (isCancelled) return;
        isGlitching = true;
        glitchEndTimeoutId = setTimeout(() => {
          isGlitching = false;
          startGlitchLoop();
        }, glitchDuration);
      }, glitchInterval);
    };

    if (glitchMode) startGlitchLoop();

    const run = timestamp => {
      if (isCancelled) return;

      if (timestamp - lastFrameTime < frameDuration) {
        animationFrameId = window.requestAnimationFrame(run);
        return;
      }
      lastFrameTime = timestamp;

      ctx.clearRect(
        -fuzzRange - 20,
        -fuzzRange - 10,
        offscreenWidth + 2 * (fuzzRange + 20),
        tightHeight + 2 * (fuzzRange + 10)
      );

      if (isClicking) {
        targetIntensity = 1;
      } else if (isGlitching) {
        targetIntensity = 0.9;
      } else if (isHovering) {
        targetIntensity = hoverIntensity;
      } else {
        targetIntensity = baseIntensity;
      }

      if (transitionDuration > 0) {
        const step = 1 / (transitionDuration / (frameDuration / 16.6));
        if (currentIntensity < targetIntensity) {
          currentIntensity = Math.min(currentIntensity + step, targetIntensity);
        } else if (currentIntensity > targetIntensity) {
          currentIntensity = Math.max(currentIntensity - step, targetIntensity);
        }
      } else {
        currentIntensity = targetIntensity;
      }

      for (let j = 0; j < tightHeight; j++) {
        let dx = 0,
          dy = 0;
        if (direction === 'horizontal' || direction === 'both') {
          dx = Math.floor(currentIntensity * (Math.random() - 0.5) * fuzzRange);
        }
        if (direction === 'vertical' || direction === 'both') {
          dy = Math.floor(currentIntensity * (Math.random() - 0.5) * fuzzRange * 0.5);
        }
        ctx.drawImage(offscreen, 0, j, offscreenWidth, 1, dx, j + dy, offscreenWidth, 1);
      }
      animationFrameId = window.requestAnimationFrame(run);
    };

    animationFrameId = window.requestAnimationFrame(run);

    const isInsideTextArea = (x, y) => {
      return x >= interactiveLeft && x <= interactiveRight && y >= interactiveTop && y <= interactiveBottom;
    };

    const handleMouseMove = e => {
      if (!enableHover) return;
      const rect = canvas.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      isHovering = isInsideTextArea(x, y);
    };

    const handleMouseLeave = () => {
      isHovering = false;
    };

    const handleClick = () => {
      if (!clickEffect) return;
      isClicking = true;
      clearTimeout(clickTimeoutId);
      clickTimeoutId = setTimeout(() => {
        isClicking = false;
      }, 200);
    };

    const handleTouchMove = e => {
      if (!enableHover) return;
      const rect = canvas.getBoundingClientRect();
      const touch = e.touches[0];
      const x = touch.clientX - rect.left;
      const y = touch.clientY - rect.top;
      isHovering = isInsideTextArea(x, y);
    };

    const handleTouchEnd = () => {
      isHovering = false;
    };

    if (enableHover) {
      canvas.addEventListener('mousemove', handleMouseMove);
      canvas.addEventListener('mouseleave', handleMouseLeave);
      canvas.addEventListener('touchmove', handleTouchMove, { passive: true });
      canvas.addEventListener('touchend', handleTouchEnd);
    }

    if (clickEffect) {
      canvas.addEventListener('click', handleClick);
    }
  };

  init();

  return {
    destroy: () => {
      isCancelled = true;
      window.cancelAnimationFrame(animationFrameId);
      clearTimeout(glitchTimeoutId);
      clearTimeout(glitchEndTimeoutId);
      clearTimeout(clickTimeoutId);
    }
  };
}

export default mountFuzzyText;
