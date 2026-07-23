// Single source of truth for the Flarelink auth module version.
//
// Imported by both:
//   - auth-module/worker.ts (baked into the bundled customer Worker; surfaces
//     at /__flarelink and goes into the rendered flarelinkAuth.ts header).
//   - server/auth-module/worker-source.ts (used by Flarelink itself when
//     recording flarelinkAuthVersion on new auth_module_deployment rows + for
//     /api/auth-module/version dashboard responses).
//
// Bump here when shipping a new auth-module release. Both sides pick it up
// next build.

export const FLARELINK_AUTH_VERSION = '0.3.1';
