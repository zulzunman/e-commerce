import { defineConfig } from "vite";

export default defineConfig(async () => {
    const laravel = await import("laravel-vite-plugin");

    return {
        plugins: [
            laravel.default({
                input: ["resources/css/app.css", "resources/js/app.js"],
                refresh: true,
            }),
        ],
    };
});
