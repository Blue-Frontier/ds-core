module.exports = {
  fireError (e) {
    if (process.send) {
      // IPC 通道可能已关闭（父进程退出，CLI 场景常见）：直接 send 会抛 ERR_IPC_CHANNEL_CLOSED
      if (process.connected && typeof process.send === 'function') {
      process.send({ type: 'error', event: e, message: e.message })
      }
    }
  },
  fireStatus (status) {
    if (process.send) {
      // IPC 通道可能已关闭（父进程退出，CLI 场景常见）：直接 send 会抛 ERR_IPC_CHANNEL_CLOSED
      if (process.connected && typeof process.send === 'function') {
      process.send({ type: 'status', event: status })
      }
    }
  },
}
