// clean case: Math.random for presentation only — no security material
const TESTIMONIALS = ["great", "fast", "lovely"];

export function pickTestimonial(): string {
  const idx = Math.floor(Math.random() * TESTIMONIALS.length);
  return TESTIMONIALS[idx];
}
