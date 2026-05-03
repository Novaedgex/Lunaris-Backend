import express from 'express';
import supabase from '../lib/Supabase.js';
import item from '../Items.json' with { type: 'json' };
const router = express.Router();

router.get("/get/warehouses", async (req, res) => {
    return res.status(200).json(item.warehouses)
})

router.post("/check/warehouses", async (req, res) => {
    const { UUID } = req.body;

    // 1. Check if UUID was actually provided to prevent unnecessary DB calls
    if (!UUID) {
        return res.status(400).json({ status: "error", message: "UUID is required" });
    }

    try {
        // 2. Select warehouses where owner matches UUID
        const { data: Bought, error: BoughtError } = await supabase
            .from("Warehouses")
            .select('*')
            .eq("owner", UUID); // No need for template literal `${}` if it's already a string

        if (BoughtError) {
            // 3. Use 'BoughtError' here, as 'error' is not defined in this scope
            return res.status(500).json({ status: "error", message: BoughtError.message });
        }

        return res.status(200).json(Bought);

    } catch (error) {
        // 4. Catch unexpected server/network errors
        return res.status(500).json({ status: "error", message: error.message || "Internal Server Error" });
    }
});

router.get("/get/racks", async (req, res) => {
    return res.status(200).json(item.racks)
})

router.get("/get/servers", async (req, res) => {
    return res.status(200).json(item.servers)
})


export default router