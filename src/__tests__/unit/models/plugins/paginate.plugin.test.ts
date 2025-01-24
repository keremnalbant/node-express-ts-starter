import { Document, PaginateModel, Schema, Types, model } from 'mongoose';

import { paginate } from '../../../../models/plugins/paginate.plugin';

interface IProject {
  name: string;
  tasks?: ITask[];
}
interface IProjectDocument extends IProject, Document {}
interface IProjectModel extends PaginateModel<IProjectDocument> {}

interface ITask {
  name: string;
  project: Types.ObjectId;
}
interface ITaskDocument extends ITask, Document {}
interface ITaskModel extends PaginateModel<ITaskDocument> {}

const projectSchema = new Schema({
  name: {
    required: true,
    type: String,
  },
});

projectSchema.virtual('tasks', {
  foreignField: 'project',
  localField: '_id',
  ref: 'Task',
});

projectSchema.plugin(paginate);
const Project = model<IProjectDocument, IProjectModel>('Project', projectSchema);

const taskSchema = new Schema({
  name: {
    required: true,
    type: String,
  },
  project: {
    ref: 'Project',
    required: true,
    type: Types.ObjectId,
  },
});

taskSchema.plugin(paginate);

const Task = model<ITaskDocument, ITaskModel>('Task', taskSchema);

describe('paginate plugin', () => {
  describe('populate option', () => {
    test('should populate the specified data fields', async () => {
      const project = await Project.create({ name: 'Project One' });
      const task = await Task.create({ name: 'Task One', project: project._id });

      const taskPages = await Task.paginate({ _id: task._id }, { populate: 'project' });

      expect(taskPages.results[0].project).toHaveProperty('_id', project._id);
    });

    test('should populate nested fields', async () => {
      const project = await Project.create({ name: 'Project One' });
      const task = await Task.create({ name: 'Task One', project: project._id });

      const projectPages = await Project.paginate({ _id: project._id }, { populate: 'tasks.project' });
      const { tasks } = projectPages.results[0];

      expect(tasks).toHaveLength(1);
      expect(tasks[0]).toHaveProperty('_id', task._id);
      expect(tasks[0].project).toHaveProperty('_id', project._id);
    });
  });
});
