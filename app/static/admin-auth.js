// static/admin-auth.js

class AdminAuth {
    constructor() {
        this.apiKey = null;
        this.userRole = null;
    }

    async initialize() {
        try {
            // Get current user info
            const userResponse = await fetch('/api/user');
            if (!userResponse.ok) {
                throw new Error('Not authenticated');
            }
            
            const userData = await userResponse.json();
            this.userRole = userData.role;
            
            // Get or create API key for the current user
            await this.ensureApiKey();
            
            return true;
        } catch (error) {
            console.error('Admin auth initialization failed:', error);
            // Redirect to login if not authenticated
            window.location.href = '/';
            return false;
        }
    }

    async ensureApiKey() {
        try {
            // Try to get existing API keys
            const keysResponse = await fetch('/api/user/keys');
            if (keysResponse.ok) {
                const keys = await keysResponse.json();
                if (keys.length > 0) {
                    this.apiKey = keys[0].api_key;
                    console.log('Using existing API key');
                    return;
                }
            }
            
            // Create new API key if none exists
            const createResponse = await fetch('/api/user/keys', {
                method: 'POST'
            });
            
            if (createResponse.ok) {
                const result = await createResponse.json();
                this.apiKey = result.api_key;
                console.log('Created new API key');
            } else {
                throw new Error('Failed to create API key');
            }
        } catch (error) {
            console.error('Error ensuring API key:', error);
            throw error;
        }
    }

    getAuthHeaders() {
        if (!this.apiKey) {
            throw new Error('API key not available');
        }
        
        return {
            'X-API-Key': this.apiKey,
            'Content-Type': 'application/json'
        };
    }

    async fetchWithAuth(url, options = {}) {
        if (!this.apiKey) {
            await this.ensureApiKey();
        }
        
        const authHeaders = this.getAuthHeaders();
        const mergedOptions = {
            ...options,
            headers: {
                ...authHeaders,
                ...options.headers
            }
        };
        
        const response = await fetch(url, mergedOptions);
        
        // If unauthorized, try to refresh API key and retry once
        if (response.status === 401) {
            console.log('API key expired, refreshing...');
            await this.ensureApiKey();
            mergedOptions.headers['X-API-Key'] = this.apiKey;
            return await fetch(url, mergedOptions);
        }
        
        return response;
    }

    // Helper method for common API calls
    async get(url) {
        return await this.fetchWithAuth(url);
    }

    async post(url, data = {}) {
        return await this.fetchWithAuth(url, {
            method: 'POST',
            body: JSON.stringify(data)
        });
    }

    async put(url, data = {}) {
        return await this.fetchWithAuth(url, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    }

    async delete(url) {
        return await this.fetchWithAuth(url, {
            method: 'DELETE'
        });
    }
}

// Create global instance
window.adminAuth = new AdminAuth();