import supabase from "@supabase/supabase-js";
import dotenv from "dotenv";

dotenv.config();
const supabaseUrl = "https://eimjyujfiiacrxhojtyr.supabase.co";
const supabaseKey = env.SUPABASE_KEY;
const supabase = supabase.createClient(supabaseUrl, supabaseKey);


export default supabase;