export interface LogLine {
  id: string
  timestamp: string
  source: string
  level: 'ERROR' | 'WARN' | 'INFO' | 'DEBUG'
  content: string
}

export interface FileWatchdogConfig {
  type: 'file'
  path: string
}

export interface SyslogConfig {
  type: 'syslog'
  port: number
  protocol: 'UDP' | 'TCP'
}

export interface PollConfig {
  type: 'poll'
  url: string
  intervalSeconds: number
  authHeader?: string
}

export type WatchdogConfig = FileWatchdogConfig | SyslogConfig | PollConfig

export interface WatchdogStats {
  filesDetected?: number
  lastIngested?: string
  eventsPerMin?: number
  packetsPerSec?: number
  lastPolled?: string
}

export interface WatchdogConnection {
  id: string
  type: 'file' | 'syslog' | 'poll'
  status: 'WATCHING' | 'STOPPED' | 'ERROR'
  config: WatchdogConfig
  stats: WatchdogStats
  liveLines: LogLine[]
  createdAt: string
}
