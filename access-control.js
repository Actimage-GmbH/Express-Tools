function AccessController (cfg) {
    // Get access control config
    const roles = cfg;
    
    
    let buildPath = req => req.method.toUpperCase() + (req.app.basePath || req.baseUrl || '') + req.route.path;
    
    // Check if reqest path is under access control
    let checkPath = req => {
        let access = roles[buildPath(req)];
        return typeof access !== "undefined" && access !== null;
    };
    
    // Check if given user can access the request
    let checkAccesses = (req, user) => {
        // Retrieve access definition with request method and path
        let access = roles[buildPath(req)];
        let allowedScope = access.allowedScope;

        // List roles
        let r = Object.keys(access);

        // Check if the access is by ownership and verify ownership if required
        let getAccessRight = a => {
            if (typeof access[a] === 'boolean') {
                return true;
            } else {
                let pk = Object.keys(access[a]);
                for (let p in pk) {
                    if (req.params[pk[p]] === user[access[a][pk[p]]]) {
                        return true;
                    }
                }
            }
            return false;
        };

        // Check if the accessing user has the right scope in clients scope list. If self access is set check it too
        let checkingScope = () => {
            let state = false
            for (let key in allowedScope) {
                var val = allowedScope[key];

                for (let i in user.clients) {
                    let client = user.clients[i];
                    for (let j in client.scope) {
                        let scope = client.scope[j];
                        if (key === scope) {
                            if (val.constructor === Object) {
                                let pk = Object.keys(allowedScope[key]);
                                for (let p in pk) {
                                    if (req.params[pk[p]] === user[allowedScope[key][pk[p]]]) {
                                        return true;
                                    }
                                }
                            } else {
                                return true;
                            }
                        }
                    }
                }
            }
            return false;
        }

        // Check active and authenticated access rights first
        let activeAuthenticated = undefined;

        // Check if the user have the proper access
        for (let a in r) {
            if (r[a] === ROLE_KEY.AUTENTICATED) {
                if (getAccessRight(r[a])) activeAuthenticated = true;
            } else if (r[a] === ROLE_KEY.ACTIVE && user.active === true) {
                if (getAccessRight(r[a])) activeAuthenticated = true;
                ;
            } else if ((user.roles || []).indexOf(r[a]) >= 0 && user.active === true) {
                if (getAccessRight(r[a])) return true;
            } else if (r[a] === ROLE_KEY.ALLOWED_SCOPE) {
                // Check scopes only if activeAuthenticated is not false
                if (activeAuthenticated || activeAuthenticated === undefined) {
                    if (checkingScope()) return true;
                }
            }
        }
        return false;
    };
    this.checkAccesses = checkAccesses;
    this.checkPath = checkPath;
};

// Declare some specific keys to use as access control like roles but more general (cf: access control for any authenticated user, or for any authenticated and active user)
const ROLE_KEY = {
    AUTENTICATED: "$authenticated",
    ACTIVE: "$active",
    ALLOWED_SCOPE: "allowedScope"
};


AccessController.prototype.ROLE_KEY = ROLE_KEY;


module.exports = (cfg) => new AccessController(cfg);
