CREATE TABLE groups (
    id TEXT PRIMARY KEY, -- UUID for the group
    name TEXT UNIQUE NOT NULL, -- Group name, used for external references
    description TEXT, -- Optional description for the group
    active BOOLEAN NOT NULL DEFAULT TRUE, -- Whether the group is active
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, -- When the group was created
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP -- When the group was last updated
);

CREATE TABLE user_groups (
    id TEXT PRIMARY KEY, -- UUID for the membership
    user_id TEXT NOT NULL, -- User ID
    group_id TEXT NOT NULL, -- Group ID
    start_date DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, -- When membership starts
    end_date DATETIME, -- When membership ends (NULL for infinite)
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, -- When the membership was created
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE RESTRICT,
    FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE RESTRICT
);

CREATE INDEX idx_groups_name ON groups (name);
CREATE INDEX idx_groups_active ON groups (active);
CREATE INDEX idx_user_groups_user_id ON user_groups (user_id);
CREATE INDEX idx_user_groups_group_id ON user_groups (group_id);
CREATE INDEX idx_user_groups_end_date ON user_groups (end_date);
