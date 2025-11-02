# Tool Instructions Dialog Feature

## Overview
Added comprehensive instructions popup for security tools with copyable commands and updated evidence file timestamp format.

## Changes Implemented

### 1. Tool Instructions Dialog
**Location**: `src/ui/tool_execution.rs`

Added a rich instructions dialog that displays:
- **Tool Description**: What the tool does and its capabilities
- **Installation Instructions**: Platform-specific installation commands (copyable)
- **Common Examples**: Real-world usage scenarios with copyable commands
- **Common Flags**: Comprehensive flag reference with descriptions
- **Tips & Best Practices**: Expert advice for effective tool usage

**Features**:
- ✅ Scrollable dialog (800x600px) for comprehensive content
- ✅ Copyable command snippets with "📋 Copy" buttons
- ✅ Clipboard integration for one-click command copying
- ✅ Organized sections with frames for visual clarity
- ✅ Modal dialog that doesn't block application

### 2. Nmap Instructions
Comprehensive guide including:
- **8 Installation Commands** (Ubuntu, Red Hat, macOS)
- **7 Usage Examples**:
  - Basic TCP SYN scan
  - Port scanning with version detection
  - Aggressive scan (OS detection, scripts, traceroute)
  - Subnet scanning
  - Vulnerability scanning with NSE scripts
  - Full 65535 port scan
  - Fast scan (top 100 ports)
- **15 Common Flags**: -sS, -sT, -sU, -sV, -O, -A, -p, -F, -T, --script, -oN/-oX, -v, -Pn
- **6 Tips**: Permission requirements, timing templates, flag combinations, NSE script locations, debugging, web server enumeration

### 3. Gobuster Instructions
Comprehensive guide including:
- **10 Installation Commands** (GitHub releases, Go install, apt)
- **6 Usage Examples**:
  - Directory/file brute-forcing
  - DNS subdomain enumeration
  - Virtual host discovery
  - Extension-based scanning
  - Multi-threaded fast scanning
  - Custom User-Agent and cookies
- **15 Common Flags**: dir/dns/vhost modes, -u, -d, -w, -x, -t, -s, -b, -a, -c, -o, -k, -q
- **7 Tips**: Wordlist selection, backup file extensions, thread tuning, WordPress scanning, tool combination, status code filtering

### 4. Updated Evidence Timestamp Format
**Location**: `src/ui/handlers.rs` - `save_tool_output()` function

**Old Format**: Unix timestamp milliseconds (e.g., `nmap_scanme.nmap.org_1730554890123_0.txt`)
**New Format**: MonDDHHMM (e.g., `nmap_scanme.nmap.org_Nov021430_0.txt`)

**Benefits**:
- ✅ Human-readable timestamps
- ✅ Sortable by filename (chronological order)
- ✅ Month abbreviation (Nov, Dec, Jan, etc.)
- ✅ Day of month (01-31)
- ✅ Hour and minute (24-hour format)

**Example Filenames**:
```
nmap_192.168.1.1_Nov021430_0.txt
gobuster_example.com_Nov021532_0.txt
nmap_scanme.nmap.org_Dec251200_0.txt
```

### 5. UI Integration
**Location**: `src/ui/handlers.rs` - `setup_tool_execution_handlers()`

- Added "ℹ️ Instructions" button next to "Execute Tool" button
- Button opens instructions dialog for currently selected tool
- Dynamically shows instructions based on tool selector value
- Non-blocking modal dialog design

## User Experience Flow

### Opening Instructions
1. User selects tool from dropdown (Nmap or Gobuster)
2. User clicks "ℹ️ Instructions" button
3. Dialog opens showing comprehensive tool guide
4. User can scroll through sections
5. User clicks "📋 Copy" next to any command to copy it
6. User clicks "Close" when done

### Copying Commands
1. User finds relevant command example
2. User clicks "📋 Copy" button
3. Command is copied to system clipboard
4. User can paste into Target/Arguments fields
5. Or paste into external terminal

## Technical Implementation

### Data Structures
```rust
struct ToolInstructions {
    name: String,
    description: &'static str,
    installation: Vec<String>,
    examples: Vec<ToolExample>,
    common_flags: Vec<ToolFlag>,
    tips: Vec<&'static str>,
}

struct ToolExample {
    description: String,
    command: String,
}

struct ToolFlag {
    flag: String,
    description: String,
}
```

### Key Functions
- `get_tool_instructions(tool_id: &str) -> ToolInstructions` - Returns tool-specific data
- `create_copyable_command_row(command: &str) -> GtkBox` - Creates command row with copy button
- `show_instructions_dialog(&self, window: &gtk4::Window)` - Builds and displays dialog
- `connect_info_clicked<F>(&self, callback: F)` - Wires up info button handler

### Widget Hierarchy
```
Dialog
└── ScrolledWindow
    └── VBox
        ├── Description Label
        ├── Installation Frame
        │   └── VBox (copyable commands)
        ├── Examples Frame
        │   └── VBox (titles + copyable commands)
        ├── Flags Frame
        │   └── VBox (flag descriptions)
        └── Tips Frame
            └── VBox (tip labels)
```

## Code Quality

### Maintainability
- ✅ Modular design with separate data structures
- ✅ Easy to add new tools (just add match arm in `get_tool_instructions`)
- ✅ Reusable `create_copyable_command_row` function
- ✅ Clean separation of data and UI logic

### Extensibility
To add a new tool:
1. Add tool to `tool_selector` dropdown
2. Add match arm in `get_tool_instructions()` with:
   - Tool name and description
   - Installation commands
   - Usage examples
   - Common flags
   - Tips
3. No UI code changes needed

### Testing Checklist
- [x] Build successful (0 errors, 26 warnings)
- [x] Application runs
- [ ] Nmap instructions dialog opens
- [ ] Gobuster instructions dialog opens
- [ ] Copy buttons work
- [ ] Commands copy to clipboard
- [ ] Dialog scrolls properly
- [ ] Close button dismisses dialog
- [ ] Tool execution saves with new timestamp format
- [ ] Evidence files have MonDDHHMM format

## Files Modified

1. **src/ui/tool_execution.rs** (+283 lines)
   - Added `ToolInstructions`, `ToolExample`, `ToolFlag` structs
   - Added `info_button` field to `ToolExecutionPanel`
   - Added `connect_info_clicked()` method
   - Added `show_instructions_dialog()` method
   - Added `create_copyable_command_row()` function
   - Added `get_tool_instructions()` function with Nmap/Gobuster data
   - Made `ToolExecutionPanel` cloneable

2. **src/ui/handlers.rs** (lines 34-40, 293-299)
   - Updated `save_tool_output()` timestamp format (Unix ms → MonDDHHMM)
   - Wired up info button click handler in `setup_tool_execution_handlers()`

## Example Usage

### Scenario 1: New User Learning Nmap
1. User opens PT Journal
2. Selects "Nmap - Port Scanner" from dropdown
3. Clicks "ℹ️ Instructions"
4. Dialog shows comprehensive Nmap guide
5. User reads "Basic TCP SYN scan" example
6. User clicks "📋 Copy" on `nmap -sS scanme.nmap.org`
7. User pastes into Target field: `scanme.nmap.org`
8. User pastes into Arguments field: `-sS`
9. User clicks "Execute Tool"
10. Output saved as: `nmap_scanme.nmap.org_Nov021430_0.txt`

### Scenario 2: Experienced User Quick Reference
1. User already knows Gobuster
2. Needs to remember specific flag syntax
3. Clicks "ℹ️ Instructions"
4. Scrolls to "Common Flags" section
5. Finds: `-x <extensions>` - File extensions to search
6. Closes dialog
7. Enters: `-x php,html,txt` in Arguments field

### Scenario 3: Installation Help
1. User on new Kali Linux install
2. Doesn't have Gobuster installed
3. Clicks "ℹ️ Instructions"
4. Scrolls to "Installation" section
5. Sees: `sudo apt install gobuster`
6. Clicks "📋 Copy"
7. Opens terminal
8. Pastes and runs command
9. Returns to PT Journal and executes tool

## Benefits

### For Users
- ✅ **No external documentation needed** - Everything in-app
- ✅ **Copy-paste efficiency** - One click to copy commands
- ✅ **Learning resource** - Examples teach proper usage
- ✅ **Quick reference** - Flag descriptions always accessible
- ✅ **Installation guide** - Platform-specific commands

### For Documentation
- ✅ **Readable timestamps** - Evidence files easy to identify
- ✅ **Chronological sorting** - Filename-based ordering works
- ✅ **Evidence organization** - Clear when tools were run

### For Reporting
- ✅ **Clear timeline** - MonDDHHMM shows when scans occurred
- ✅ **Professional** - Readable filenames in evidence folders
- ✅ **Tool identification** - Filename shows tool used

## Future Enhancements

### Additional Tools
- [ ] Nikto instructions (web server scanner)
- [ ] SQLMap instructions (SQL injection)
- [ ] Burp Suite integration guide
- [ ] Metasploit basics

### Advanced Features
- [ ] "Paste into Fields" button - auto-populate target/args
- [ ] Search within instructions dialog
- [ ] Recently used commands history
- [ ] Custom tool templates (user-defined)
- [ ] Video tutorials (embedded or links)

### Timestamp Options
- [ ] User preference: MonDDHHMM vs YYYY-MM-DD-HHMM vs Unix
- [ ] Timezone display in evidence metadata
- [ ] Duration calculation (start time + execution time)

## Commit Message
```
feat: Add comprehensive tool instructions dialog with copyable commands

- Added "ℹ️ Instructions" button next to Execute Tool button
- Created rich instructions dialog with:
  * Tool description and capabilities
  * Platform-specific installation commands
  * Common usage examples with real-world scenarios
  * Comprehensive flag reference
  * Tips & best practices
- Implemented copyable command snippets with "📋 Copy" buttons
- Added full Nmap instructions (7 examples, 15 flags, 6 tips)
- Added full Gobuster instructions (6 examples, 15 flags, 7 tips)
- Updated evidence timestamp format: Unix ms → MonDDHHMM
  * Example: nmap_target_Nov021430_0.txt
  * Human-readable and chronologically sortable

Files modified:
- src/ui/tool_execution.rs: Dialog implementation (+283 lines)
- src/ui/handlers.rs: Info button wiring + timestamp format

Benefits:
- No external documentation needed
- One-click command copying to clipboard
- Learning resource for new users
- Quick reference for experienced users
- Professional, readable evidence filenames
```
