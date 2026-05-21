---
name: Modern Systematic Aesthetic
colors:
  surface: '#f9f9fb'
  surface-dim: '#d9dadc'
  surface-bright: '#f9f9fb'
  surface-container-lowest: '#ffffff'
  surface-container-low: '#f3f3f5'
  surface-container: '#eeeef0'
  surface-container-high: '#e8e8ea'
  surface-container-highest: '#e2e2e4'
  on-surface: '#1a1c1d'
  on-surface-variant: '#46464a'
  inverse-surface: '#2f3132'
  inverse-on-surface: '#f0f0f2'
  outline: '#77767b'
  outline-variant: '#c7c6ca'
  surface-tint: '#5f5e60'
  primary: '#030304'
  on-primary: '#ffffff'
  primary-container: '#1d1d1f'
  on-primary-container: '#868587'
  inverse-primary: '#c8c6c8'
  secondary: '#005ab7'
  on-secondary: '#ffffff'
  secondary-container: '#0372e4'
  on-secondary-container: '#fefcff'
  tertiary: '#020305'
  on-tertiary: '#ffffff'
  tertiary-container: '#1c1d21'
  on-tertiary-container: '#85858a'
  error: '#ba1a1a'
  on-error: '#ffffff'
  error-container: '#ffdad6'
  on-error-container: '#93000a'
  primary-fixed: '#e4e2e4'
  primary-fixed-dim: '#c8c6c8'
  on-primary-fixed: '#1b1b1d'
  on-primary-fixed-variant: '#474649'
  secondary-fixed: '#d7e2ff'
  secondary-fixed-dim: '#abc7ff'
  on-secondary-fixed: '#001b3f'
  on-secondary-fixed-variant: '#00458f'
  tertiary-fixed: '#e3e2e7'
  tertiary-fixed-dim: '#c7c6cb'
  on-tertiary-fixed: '#1a1b1f'
  on-tertiary-fixed-variant: '#46464b'
  background: '#f9f9fb'
  on-background: '#1a1c1d'
  surface-variant: '#e2e2e4'
typography:
  display:
    fontFamily: Inter
    fontSize: 48px
    fontWeight: '600'
    lineHeight: '1.1'
    letterSpacing: -0.02em
  headline-lg:
    fontFamily: Inter
    fontSize: 32px
    fontWeight: '600'
    lineHeight: '1.2'
    letterSpacing: -0.015em
  headline-md:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: '1.3'
    letterSpacing: -0.01em
  body-lg:
    fontFamily: Inter
    fontSize: 17px
    fontWeight: '400'
    lineHeight: '1.5'
    letterSpacing: -0.01em
  body-md:
    fontFamily: Inter
    fontSize: 15px
    fontWeight: '400'
    lineHeight: '1.5'
    letterSpacing: '0'
  label-md:
    fontFamily: Inter
    fontSize: 13px
    fontWeight: '500'
    lineHeight: '1.4'
    letterSpacing: 0.01em
  caption:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '400'
    lineHeight: '1.4'
    letterSpacing: 0.02em
rounded:
  sm: 0.25rem
  DEFAULT: 0.5rem
  md: 0.75rem
  lg: 1rem
  xl: 1.5rem
  full: 9999px
spacing:
  base: 8px
  xs: 4px
  sm: 12px
  md: 24px
  lg: 40px
  xl: 64px
  gutter: 20px
  margin: max(24px, 5vw)
---

## Brand & Style

The design system is anchored in "Digital Quietude"—a philosophy that prioritizes content clarity over decorative elements. It targets professional environments and premium consumer experiences where efficiency and sophistication are paramount. 

The aesthetic is heavily inspired by Modern Minimalism and the Human Interface Guidelines (HIG). It evokes an emotional response of organized calm, precision, and reliability. By utilizing high-contrast typography against vast, pure-white canvases, the system creates a "smart" atmosphere that feels both high-tech and approachable.

## Colors

The palette is intentionally restrained to maximize the impact of content. 

- **Backgrounds:** Exclusively pure white (#FFFFFF) for primary surfaces to maintain a laboratory-clean feel. 
- **Typography:** Deep black (#1D1D1F) provides maximum legibility and a premium editorial look. 
- **Accents:** A precision blue (#0071E3) is used sparingly for interactive cues and primary actions, ensuring the "smart" feel is functionally reinforced.
- **Borders:** Soft gray (#E5E5E7) is used to define boundaries without introducing visual noise.

## Typography

This design system utilizes **Inter** to achieve a systematic, utilitarian aesthetic that mirrors San Francisco. The typographic hierarchy relies on weight and optical sizing rather than color variation.

Tight letter-spacing is applied to larger headlines to create a cohesive "block" of text, while body copy maintains generous leading (1.5x) to ensure breathability and high scan-rates. Use SemiBold (600) for all primary headings to establish a clear information architecture.

## Layout & Spacing

The layout philosophy follows a **Fixed-Fluid Hybrid Grid**. Content is housed in a centered container with a maximum width of 1200px to prevent excessive line lengths on wide displays. 

A strict 8px spacing rhythm dictates all spatial relationships. Generous whitespace is the primary tool for grouping; elements that are related should be separated by `sm` (12px), while distinct sections must use `lg` (40px) or `xl` (64px) to create the "airy" feel characteristic of premium interfaces.

## Elevation & Depth

Depth is conveyed through **Low-Contrast Outlines** and **Ambient Shadows**. 

1. **Level 0 (Flat):** Primary background surfaces.
2. **Level 1 (Subtle):** Use a 1px border (#E5E5E7) for cards and containers. No shadow.
3. **Level 2 (Raised):** Use for active states or floating menus. Apply a very diffused, low-opacity shadow (Color: #000000, Opacity: 4%, Blur: 20px, Y-Offset: 4px).
4. **Level 3 (Overlay):** Used for modals. Increase shadow opacity to 8% and blur to 40px to create a significant sense of separation.

Avoid heavy blacks or saturated colors in shadows; they should feel like a natural consequence of light hitting a physical surface.

## Shapes

The shape language is defined by "Squircle-lite" geometry. Standard components like buttons and input fields use a **0.5rem (8px)** radius. Larger containers, such as cards and modals, utilize a **0.75rem (12px)** radius to create a softer, more inviting appearance.

Interactive elements should never be sharp-edged. The consistency of these radii across the system reinforces the "smart" and engineered feel of the product.

## Components

- **Buttons:** Primary buttons feature the deep black background with white text. Secondary buttons are ghost-style with the soft gray border. Use a horizontal padding of 20px and vertical of 10px.
- **Input Fields:** Use a white background with the soft gray border. On focus, the border should transition to a 2px stroke of the primary black or accent blue.
- **Cards:** Cards should be white-on-white with the soft gray border (#E5E5E7). Reserve shadows only for "hover" interactions to indicate playability.
- **Chips:** Small, pill-shaped elements with a light gray background (#F5F5F7) and #1D1D1F text. Use for tags or status indicators.
- **Icons:** Use thin-stroke (2pt) monolinear icons. Icons should always be accompanied by labels or have very high metaphorical clarity.
- **Lists:** Use subtle dividers (1px, #E5E5E7) that inset from the left to align with the text, not the icon, mirroring the iOS list style.