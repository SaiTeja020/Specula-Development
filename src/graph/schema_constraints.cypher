// Specula Knowledge Graph Schema Constraints
//
// Defines unique constraints and indexes for the DFKG.
// Must be applied before any data ingestion.
//
// Reference: specula_ingestion_final_plan.md §8.2

// 1. Unique Constraints (Enforces entity uniqueness)

CREATE CONSTRAINT host_uid_unique IF NOT EXISTS FOR (h:Host) REQUIRE h.uid IS UNIQUE;
CREATE CONSTRAINT process_uid_unique IF NOT EXISTS FOR (p:Process) REQUIRE p.uid IS UNIQUE;
CREATE CONSTRAINT endpoint_uid_unique IF NOT EXISTS FOR (e:NetworkEndpoint) REQUIRE e.uid IS UNIQUE;
CREATE CONSTRAINT network_event_uid_unique IF NOT EXISTS FOR (e:Event) REQUIRE e.uid IS UNIQUE;
CREATE CONSTRAINT case_uid_unique IF NOT EXISTS FOR (c:Case) REQUIRE c.uid IS UNIQUE;
CREATE CONSTRAINT user_uid_unique IF NOT EXISTS FOR (u:User) REQUIRE u.uid IS UNIQUE;
CREATE CONSTRAINT file_uid_unique IF NOT EXISTS FOR (f:File) REQUIRE f.uid IS UNIQUE;

// §5.2: Entity-level uniqueness for DFKG consumer writes (skeleton phase)
// Prevents duplicate nodes from Kafka consumer retries / message replays.
CREATE CONSTRAINT entity_uid_unique IF NOT EXISTS FOR (e:Entity) REQUIRE e.uid IS UNIQUE;



// 2. Composite Indexes for Backfill Performance & Case Isolation

CREATE INDEX process_composite_idx IF NOT EXISTS FOR (n:Process) ON (n.canonical_host_id, n.timestamp);
CREATE INDEX host_composite_idx IF NOT EXISTS FOR (n:Host) ON (n.canonical_host_id, n.timestamp);
CREATE INDEX file_composite_idx IF NOT EXISTS FOR (n:File) ON (n.canonical_host_id, n.timestamp);
CREATE INDEX user_composite_idx IF NOT EXISTS FOR (n:User) ON (n.canonical_host_id, n.timestamp);
CREATE INDEX endpoint_composite_idx IF NOT EXISTS FOR (n:NetworkEndpoint) ON (n.canonical_host_id, n.timestamp);


// 3. Text Indexes for Pattern Matching

CREATE TEXT INDEX process_name_text_index IF NOT EXISTS FOR (p:Process) ON (p.process_name);
CREATE TEXT INDEX command_line_text_index IF NOT EXISTS FOR (p:Process) ON (p.command_line);
CREATE TEXT INDEX filename_text_index IF NOT EXISTS FOR (f:File) ON (f.file_name);
