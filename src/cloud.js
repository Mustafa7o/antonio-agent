import { createClient } from '@supabase/supabase-js';

const url = process.env.SUPABASE_URL;
const key = process.env.SUPABASE_PUBLISHABLE_KEY;

export const cloudEnabled = Boolean(url && key && process.env.USE_SUPABASE_DB === 'true');
export const authEnabled = Boolean(url && key);
export const supabase = authEnabled
  ? createClient(url, key, { auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false } })
  : null;

export async function verifyAccessToken(token) {
  if (!supabase || !token) return null;
  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data?.user) return null;
  return data.user;
}

export function userIdFor(user) { return user?.id || 'local'; }
