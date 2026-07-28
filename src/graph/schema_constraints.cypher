// Specula Knowledge Graph Schema Constraints
//
// Defines unique constraints and indexes for the DFKG.
// Must be applied before any data ingestion.
//
// Reference: specula_ingestion_final_plan.md §8.2

// 1. Unique Constraints (Enforces entity uniqueness)

// Canonical Host constraint
CREATE CONSTRAINT host_uid_unique IF NOT EXISTS
FOR (h:Host) REQUIRE h.uid IS UNIQUE;

// Process entity constraint
CREATE CONSTRAINT process_uid_unique IF NOT EXISTS
FOR (p:Process) REQUIRE p.uid IS UNIQUE;

// Network Endpoint constraint
CREATE CONSTRAINT endpoint_uid_unique IF NOT EXISTS
FOR (e:Endpoint) REQUIRE e.uid IS UNIQUE;

// User Identity constraint
CREATE CONSTRAINT user_uid_unique IF NOT EXISTS
FOR (u:User) REQUIRE u.uid IS UNIQUE;

// File/Artifact constraint
CREATE CONSTRAINT file_uid_unique IF NOT EXISTS
FOR (f:File) REQUIRE f.uid IS UNIQUE;


// 2. Indexes (For read query performance)

// Index on case_id to quickly isolate a case subgraph
CREATE INDEX case_id_index IF NOT EXISTS
FOR (n:Entity) ON (n.case_id);

// Text indexes for pattern matching
CREATE TEXT INDEX process_name_text_index IF NOT EXISTS
FOR (p:Process) ON (p.process_name);

CREATE TEXT INDEX command_line_text_index IF NOT EXISTS
FOR (p:Process) ON (p.command_line);

CREATE TEXT INDEX filename_text_index IF NOT EXISTS
FOR (f:File) ON (f.file_name);
